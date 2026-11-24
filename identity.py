"""Who is this agent, and which owner stands behind it?

Built on Web Bot Auth (IETF draft-ietf-webbotauth-httpsig-protocol-01), which is HTTP Message
Signatures (RFC 9421) plus three conventions:

* The agent signs each request with Ed25519 and sends a ``Signature-Agent`` header naming the HTTPS
  URL where its public keys live.
* That URL serves a JWK Set (RFC 7517). When it is the well-known path
  ``https://<domain>/.well-known/http-message-signatures-directory`` (RFC 8615), the domain's owner
  is the one vouching for the key, the same way DKIM ties a mail signature to a domain.
* ``keyid`` is the key's JWK SHA-256 thumbprint (RFC 7638 / RFC 8037), so a key can't be relabelled.

What this module adds for the consent network and the front door (not in the draft, which leaves
policy to the origin):

* A trust ladder the consent rules can read: unsigned < signed (valid key, no domain) <
  domain_verified < partner (a verified domain the owner has listed by name).
* Stricter local rules than the draft's minimum: the signature must also cover the method, path,
  the request body (Content-Digest, RFC 9530) and carry a nonce; lifetimes are minutes, not hours;
  each nonce is accepted once.
* Freshness for revocation: key directories are cached for at most ``cache_ttl`` seconds (default 5
  minutes) no matter what the publisher's max-age says, and the door owner can revoke a key or a
  whole agent URL locally.
* Signed receipts: the door signs each receipt it hands back with its own key, so the caller holds
  proof of what the door decided, and the door's receipt holds the hash of the caller's signature.

It proves which domain's owner stands behind a request. It does not prove the person or business
behind that domain is honest, and it says nothing about whether a request should be allowed. That
stays with the consent rules and the owner.

Pure Python plus ``cryptography`` for Ed25519. No network call happens unless a verifier is built
with the default fetcher.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

WELL_KNOWN_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
TAG = "web-bot-auth"
DIRECTORY_TAG = "http-message-signatures-directory"   # tag on the directory response's own signatures
MAX_DIRECTORY_SIG_LIFETIME = 90 * 86400                # a static directory may be signed for up to 90 days

UNSIGNED, SIGNED, DOMAIN_VERIFIED, PARTNER = "unsigned", "signed", "domain_verified", "partner"
LEVELS = (UNSIGNED, SIGNED, DOMAIN_VERIFIED, PARTNER)
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# What the consent rules can lean on at each level (documentation; the door reads config).
LEVEL_MEANING = {
    UNSIGNED: "No valid signature. Name is self reported. Read, leave a message, ask a question or ask for a call; the owner sees 'self reported'.",
    SIGNED: "Valid signature from a key at a URL that is not a domain's well-known path. "
            "Same agent as last time, but no owner named. Treated like unsigned for permissions.",
    DOMAIN_VERIFIED: "Valid signature from a key the named domain publishes at its well-known path. "
                     "That domain's owner stands behind the agent. The owner sees 'verified: <domain>'.",
    PARTNER: "Domain-verified, and the door's owner listed that domain as a partner. "
             "Gets the partner's own allow-list.",
}


# --------------------------------------------------------------------------------------------- b64
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    text = str(text)
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


# --------------------------------------------------------------------------------------------- keys
def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 thumbprint; for OKP the required members are crv, kty, x (RFC 8037 A.3)."""
    if jwk.get("kty") != "OKP":
        raise ValueError("only OKP (Ed25519) keys are supported")
    canon = json.dumps({"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canon.encode("utf-8")).digest())


def public_key_from_jwk(jwk: Mapping[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("not an Ed25519 JWK")
    raw = b64url_decode(jwk["x"])
    if len(raw) != 32:
        raise ValueError("bad Ed25519 public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


class AgentKey:
    """An Ed25519 signing key. Private bytes never leave this object except through ``to_file``."""

    def __init__(self, private: Ed25519PrivateKey):
        self._private = private
        raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
        self.keyid = jwk_thumbprint(self._jwk)

    @classmethod
    def generate(cls) -> "AgentKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_file(cls, path) -> "AgentKey":
        from pathlib import Path
        return cls(Ed25519PrivateKey.from_private_bytes(b64url_decode(Path(path).read_text().strip())))

    def to_file(self, path) -> None:
        import os
        from pathlib import Path
        raw = self._private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption())
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(b64url(raw) + "\n")

    def public_jwk(self, **extra: Any) -> Dict[str, Any]:
        return dict(self._jwk, kid=self.keyid, use="sig", alg="ed25519", **extra)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)


def directory(keys: Iterable[AgentKey], card: Optional[Mapping[str, Any]] = None,
              extra_jwks: Iterable[Mapping[str, Any]] = ()) -> Dict[str, Any]:
    """The JSON an owner publishes at https://<domain>/.well-known/http-message-signatures-directory.

    ``card`` is optional display metadata in Signature Agent Card / OAuth client-metadata terms
    (client_name, client_uri, contacts) plus ``acts_for``. Verifiers show it; they never trust it more
    than the domain it came from, and no permission depends on it.
    """
    doc: Dict[str, Any] = {"keys": [k.public_jwk() for k in keys] + [dict(j) for j in extra_jwks]}
    if card:
        doc["agent_card"] = dict(card)
    return doc


def sign_directory_response(keys: Iterable[AgentKey], authority: str, *, now: Optional[float] = None,
                            ttl: int = 30 * 86400) -> Dict[str, str]:
    """Signature / Signature-Input headers for the directory response: one signature per key over
    ``"@authority";req`` with ``tag="http-message-signatures-directory"`` (the draft's section on
    directory responses). This proves the domain serving the file holds each key, so a mirror on
    another host fails. A static host can serve these as fixed headers; re-sign before ``expires``.
    """
    now = int(time.time() if now is None else now)
    msg = Message("GET", authority.lower(), WELL_KNOWN_PATH, "", {})
    inputs, sigs = [], []
    for i, k in enumerate(keys, 1):
        lbl = "sig%d" % i
        sp = [("alg", "ed25519"), ("keyid", k.keyid), ("created", now), ("expires", now + int(ttl)), ("tag", DIRECTORY_TAG)]
        base, pv = signature_base(msg, [("@authority", [("req", True)])], sp)
        inputs.append("%s=%s" % (lbl, pv))
        sigs.append("%s=%s" % (lbl, ser_bare(k.sign(base))))
    return {"Signature-Input": ", ".join(inputs), "Signature": ", ".join(sigs)}


def directory_signed_keys(authority: str, headers: Mapping[str, str], keys: Mapping[str, Mapping[str, Any]],
                          now: float, max_skew: int = 60) -> set:
    """Thumbprints of the directory's keys that signed this response for ``authority`` (and are in date)."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    good: set = set()
    try:
        inputs = parse_dictionary(h.get("signature-input", ""))
        sigs = parse_dictionary(h.get("signature", ""))
    except SFError:
        return good
    msg = Message("GET", authority.lower(), WELL_KNOWN_PATH, "", {})
    for lbl, (comps_raw, sp) in inputs.items():
        p = dict(sp)
        if not isinstance(comps_raw, list) or p.get("tag") != DIRECTORY_TAG or p.get("keyid") not in keys:
            continue
        created, expires = p.get("created"), p.get("expires")
        if not isinstance(created, int) or not isinstance(expires, int) or created > now + max_skew \
                or expires < now - max_skew or expires - created > MAX_DIRECTORY_SIG_LIFETIME:
            continue
        comps = [(v, list(pp)) for v, pp in comps_raw if isinstance(v, str) and not isinstance(v, Token)]
        if not any(n == "@authority" for n, _ in comps):
            continue
        sig = sigs.get(lbl, (None, []))[0]
        if not isinstance(sig, (bytes, bytearray)):
            continue
        try:
            base, _ = signature_base(msg, comps, sp)
            public_key_from_jwk(keys[p["keyid"]]).verify(bytes(sig), base)
            good.add(p["keyid"])
        except (SFError, InvalidSignature, ValueError):
            continue
    return good


# ------------------------------------------------------------------- structured fields (RFC 9651)
class SFError(ValueError):
    pass


class _P:
    """A small parser for the Structured Field shapes these headers use."""

    def __init__(self, s: str):
        self.s, self.i = s, 0

    def ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def key(self) -> str:
        start = self.i
        if not (self.peek().islower() or self.peek() == "*"):
            raise SFError("bad key at %d" % self.i)
        while self.i < len(self.s) and (self.s[self.i].islower() or self.s[self.i].isdigit() or self.s[self.i] in "_-.*"):
            self.i += 1
        return self.s[start:self.i]

    def bare(self) -> Any:
        c = self.peek()
        if c == '"':
            self.i += 1
            out = []
            while self.i < len(self.s):
                ch = self.s[self.i]
                self.i += 1
                if ch == "\\":
                    nxt = self.s[self.i: self.i + 1]
                    if nxt not in ('"', "\\"):
                        raise SFError("bad escape")
                    out.append(nxt)
                    self.i += 1
                elif ch == '"':
                    return "".join(out)
                elif ord(ch) < 0x20 or ord(ch) > 0x7E:
                    raise SFError("bad string char")
                else:
                    out.append(ch)
            raise SFError("unterminated string")
        if c == ":":
            end = self.s.index(":", self.i + 1)
            raw = self.s[self.i + 1:end]
            self.i = end + 1
            try:
                return base64.b64decode(raw, validate=True)
            except Exception as e:  # noqa: BLE001
                raise SFError("bad byte sequence") from e
        if c == "?":
            self.i += 2
            return self.s[self.i - 1] == "1"
        if c == "-" or c.isdigit():
            start = self.i
            self.i += 1
            while self.i < len(self.s) and self.s[self.i].isdigit():
                self.i += 1
            if self.peek() == ".":
                raise SFError("decimals not supported here")
            return int(self.s[start:self.i])
        if c.isalpha() or c == "*":
            start = self.i
            while self.i < len(self.s) and (self.s[self.i].isalnum() or self.s[self.i] in ":/!#$%&'*+-.^_`|~"):
                self.i += 1
            return Token(self.s[start:self.i])
        raise SFError("unexpected %r at %d" % (c, self.i))

    def params(self) -> List[Tuple[str, Any]]:
        out = []
        while self.peek() == ";":
            self.i += 1
            self.ws()
            k = self.key()
            v: Any = True
            if self.peek() == "=":
                self.i += 1
                v = self.bare()
            out.append((k, v))
        return out

    def item_or_inner(self) -> Tuple[Any, List[Tuple[str, Any]]]:
        if self.peek() == "(":
            self.i += 1
            items = []
            while True:
                self.ws()
                if self.peek() == ")":
                    self.i += 1
                    break
                v = self.bare()
                items.append((v, self.params()))
                if self.peek() not in (" ", ")"):
                    raise SFError("bad inner list")
            return items, self.params()
        v = self.bare()
        return v, self.params()

    def dictionary(self) -> Dict[str, Tuple[Any, List[Tuple[str, Any]]]]:
        out: Dict[str, Tuple[Any, List[Tuple[str, Any]]]] = {}
        self.ws()
        while self.i < len(self.s):
            k = self.key()
            if self.peek() == "=":
                self.i += 1
                out[k] = self.item_or_inner()
            else:
                out[k] = (True, self.params())
            self.ws()
            if self.i >= len(self.s):
                break
            if self.peek() != ",":
                raise SFError("expected comma at %d" % self.i)
            self.i += 1
            self.ws()
        return out


class Token(str):
    pass


def parse_dictionary(value: str):
    return _P(value.strip()).dictionary()


def parse_item(value: str):
    p = _P(value.strip())
    out = p.item_or_inner()
    if p.i != len(p.s):
        raise SFError("trailing characters")
    return out


def ser_bare(v: Any) -> str:
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return ":" + base64.b64encode(bytes(v)).decode("ascii") + ":"
    if isinstance(v, Token):
        return str(v)
    s = str(v)
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in s):
        raise SFError("string must be printable ASCII")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def ser_params(params: Sequence[Tuple[str, Any]]) -> str:
    return "".join(";" + k if v is True else ";%s=%s" % (k, ser_bare(v)) for k, v in params)


def ser_item(v: Any, params: Sequence[Tuple[str, Any]] = ()) -> str:
    if isinstance(v, list):
        return "(" + " ".join(ser_item(iv, ip) for iv, ip in v) + ")" + ser_params(params)
    return ser_bare(v) + ser_params(params)


# ----------------------------------------------------------------- signature base (RFC 9421 2.5)
Component = Tuple[str, List[Tuple[str, Any]]]  # ("signature-agent", [("key", "sig1")])


@dataclass
class Message:
    method: str
    authority: str          # host[:port] as the verifier knows itself, lowercase
    path: str               # path only, "/" when empty
    query: str = ""         # without the leading "?"
    headers: Mapping[str, str] = field(default_factory=dict)  # lowercase names

    @classmethod
    def from_url(cls, method: str, url: str, headers: Mapping[str, str]) -> "Message":
        u = urllib.parse.urlsplit(url)
        return cls(method.upper(), (u.netloc or "").lower(), u.path or "/", u.query,
                   {k.lower(): v for k, v in headers.items()})


def component_value(msg: Message, name: str, params: List[Tuple[str, Any]]) -> str:
    if name == "@method":
        return msg.method.upper()
    if name == "@authority":
        return msg.authority.lower()
    if name == "@path":
        return msg.path or "/"
    if name == "@query":
        return "?" + msg.query
    if name == "@target-uri":
        return "https://%s%s%s" % (msg.authority.lower(), msg.path or "/", ("?" + msg.query) if msg.query else "")
    if name.startswith("@"):
        raise SFError("unsupported derived component %s" % name)
    if name not in msg.headers:
        raise SFError("covered header %s is missing" % name)
    raw = " ".join(str(msg.headers[name]).split()) if "\n" in str(msg.headers[name]) else str(msg.headers[name]).strip()
    pmap = dict(params)
    if "key" in pmap:
        d = parse_dictionary(raw)
        if pmap["key"] not in d:
            raise SFError("dictionary member %s missing from %s" % (pmap["key"], name))
        v, vp = d[pmap["key"]]
        return ser_item(v, vp)
    return raw


def signature_base(msg: Message, components: Sequence[Component], sig_params: Sequence[Tuple[str, Any]]) -> Tuple[bytes, str]:
    lines = []
    seen = set()
    for name, params in components:
        ident = ser_item(name, params)
        if ident in seen:
            raise SFError("duplicate component")
        seen.add(ident)
        lines.append("%s: %s" % (ident, component_value(msg, name, list(params))))
    params_value = ser_item([(n, list(p)) for n, p in components], sig_params)
    lines.append('"@signature-params": ' + params_value)
    return "\n".join(lines).encode("utf-8"), params_value


def content_digest(body: bytes) -> str:
    return "sha-256=:%s:" % sha256_b64(body or b"")


# ------------------------------------------------------------------------------------- signing
def sign_request(key: AgentKey, method: str, url: str, headers: Mapping[str, str], body: bytes,
                 agent_url: str, *, now: Optional[float] = None, ttl: int = 60, nonce: Optional[str] = None,
                 label: str = "sig1") -> Dict[str, str]:
    """Headers to add to an outgoing request so a door can verify who sent it.

    Covers method, authority, path, the body (via Content-Digest) and the Signature-Agent member.
    """
    now = int(time.time() if now is None else now)
    nonce = nonce or b64url(secrets.token_bytes(32))
    add = {"signature-agent": "%s=%s" % (label, ser_bare(agent_url)), "content-digest": content_digest(body)}
    all_headers = {k.lower(): v for k, v in headers.items()}
    all_headers.update(add)
    msg = Message.from_url(method, url, all_headers)
    comps: List[Component] = [("@method", []), ("@authority", []), ("@path", []),
                              ("content-digest", []), ("signature-agent", [("key", label)])]
    if msg.query:
        comps.insert(3, ("@query", []))
    sp = [("created", now), ("expires", now + int(ttl)), ("keyid", key.keyid), ("alg", "ed25519"),
          ("nonce", nonce), ("tag", TAG)]
    base, params_value = signature_base(msg, comps, sp)
    sig = key.sign(base)
    add["signature-input"] = "%s=%s" % (label, params_value)
    add["signature"] = "%s=%s" % (label, ser_bare(sig))
    return {k.title(): v for k, v in add.items()}


# --------------------------------------------------------------------------------- verification
@dataclass
class Identity:
    level: str = UNSIGNED
    reason: str = "no_signature"
    rejected: bool = False            # a signature was presented and failed: the door answers 401
    agent_url: str = ""
    domain: str = ""
    keyid: str = ""
    created: int = 0
    expires: int = 0
    nonce: str = ""
    signature_sha256: str = ""        # hash of the caller's signature bytes, for both receipts
    card: Dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        if self.level == PARTNER:
            return "partner: %s" % self.domain
        if self.level == DOMAIN_VERIFIED:
            return "verified: %s" % self.domain
        if self.level == SIGNED:
            return "signed, no domain: %s" % self.agent_url
        return "self reported"

    def receipt_fields(self) -> Dict[str, Any]:
        out = {"identity": self.level, "identity_label": self.label, "identity_reason": self.reason}
        if self.domain:
            out["verified_domain"] = self.domain
        if self.agent_url:
            out["signature_agent"] = self.agent_url
        if self.keyid:
            out["keyid"] = self.keyid
        if self.signature_sha256:
            out["request_sig_sha256"] = self.signature_sha256
        return out

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def unsigned(reason: str = "no_signature") -> Identity:
    return Identity(level=UNSIGNED, reason=reason)


def rejected(reason: str, **kw: Any) -> Identity:
    return Identity(level=UNSIGNED, reason=reason, rejected=True, **kw)


class NonceStore:
    """Each (agent URL, nonce) is accepted once until the signature expires. In memory, bounded.

    A door running on several machines needs this shared (a Durable Object or KV with an atomic
    check-and-set); the interface stays the same.
    """

    def __init__(self, max_entries: int = 100_000):
        self.max_entries = max_entries
        self._seen: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_record(self, agent_url: str, nonce: str, expires: float, now: float) -> bool:
        with self._lock:
            if len(self._seen) >= self.max_entries:
                for k in [k for k, exp in self._seen.items() if exp < now]:
                    del self._seen[k]
                if len(self._seen) >= self.max_entries:
                    return False  # full of live nonces: fail closed, do not claim replay safety
            k = (agent_url, nonce)
            if k in self._seen and self._seen[k] >= now:
                return False
            self._seen[k] = float(expires)
            return True


FetchResult = Tuple[int, Mapping[str, str], bytes]
Fetcher = Callable[[str], FetchResult]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401
        return None


def safe_https_url(url: str) -> Optional[str]:
    """Reason string if the URL is not one a door should fetch (SSRF guard), else None."""
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return "bad_url"
    if u.scheme != "https":
        return "not_https"
    if u.username or u.password:
        return "credentials_in_url"
    host = (u.hostname or "").lower()
    if not host or "." not in host:
        return "bad_host"
    try:
        ipaddress.ip_address(host)
        return "ip_literal_host"
    except ValueError:
        pass
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return "local_host"
    if u.port not in (None, 443):
        return "non_default_port"
    if u.fragment:
        return "fragment_in_url"
    return None


def default_fetch(url: str, timeout: float = 3.0, max_bytes: int = 65536) -> FetchResult:
    """GET with no redirects, a short timeout and a size cap. Real network: only used in production.

    Resolution-time checks (the host resolving to a private address) belong at the edge; the door's
    Workers host has no route to private networks.
    """
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"Accept": DIRECTORY_MEDIA_TYPE + ", application/json",
                                               "User-Agent": "agent-front-door/0.2 (+key directory check)"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(max_bytes + 1)[: max_bytes + 1]
    except urllib.error.HTTPError as e:
        return e.code, {}, b""


@dataclass
class _Cached:
    keys: Dict[str, Dict[str, Any]]
    card: Dict[str, Any]
    fetched: float
    ttl: float
    ok: bool = True


def _max_age(headers: Mapping[str, str]) -> Optional[int]:
    cc = (headers or {}).get("cache-control", "")
    for part in cc.split(","):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
        if part in ("no-store", "no-cache"):
            return 0
    return None


class Verifier:
    """Checks a signed request for the door at ``authority`` and returns an Identity.

    Never raises on hostile input; every failure becomes a reason code.
    """

    def __init__(self, authority: str, *, fetch: Fetcher = default_fetch, clock: Callable[[], float] = time.time,
                 nonces: Optional[NonceStore] = None, max_skew: int = 60, max_lifetime: int = 300,
                 cache_ttl: int = 300, negative_ttl: int = 60, partners: Optional[Mapping[str, str]] = None,
                 revoked_keyids: Iterable[str] = (), revoked_agents: Iterable[str] = (),
                 require_nonce: bool = True, max_directory_bytes: int = 65536,
                 require_directory_signature: bool = True):
        self.authority = authority.lower()
        self.fetch, self.clock = fetch, clock
        self.nonces = nonces or NonceStore()
        self.max_skew, self.max_lifetime = max_skew, max_lifetime
        self.cache_ttl, self.negative_ttl = cache_ttl, negative_ttl
        self.partners = {d.lower(): slug for d, slug in (partners or {}).items()}
        self.revoked_keyids = set(revoked_keyids)
        self.revoked_agents = {normalize_agent_url(u) for u in revoked_agents}
        self.require_nonce = require_nonce
        self.max_directory_bytes = max_directory_bytes
        # The draft: a verifier relying on the domain MUST check the directory response's own signatures.
        self.require_directory_signature = require_directory_signature
        self._cache: Dict[str, _Cached] = {}
        self._lock = threading.Lock()

    # -- directory --------------------------------------------------------------------------
    def _directory(self, url: str) -> Optional[_Cached]:
        now = self.clock()
        with self._lock:
            hit = self._cache.get(url)
        if hit and now - hit.fetched < hit.ttl:
            return hit if hit.ok else None
        try:
            status, headers, body = self.fetch(url)
        except Exception:  # noqa: BLE001 - network errors are a discovery failure, not a crash
            status, headers, body = 0, {}, b""
        entry = self._parse_directory(url, status, headers, body, now)
        if entry is None:
            # A failed refresh never evicts keys we already hold (draft 6.10), but they still age out.
            if hit and hit.ok and now - hit.fetched < hit.ttl + self.negative_ttl:
                return hit
            with self._lock:
                self._cache[url] = _Cached({}, {}, now, self.negative_ttl, ok=False)
            return None
        with self._lock:
            self._cache[url] = entry
        return entry

    def _parse_directory(self, url, status, headers, body, now) -> Optional[_Cached]:
        if status != 200 or not body or len(body) > self.max_directory_bytes:
            return None
        try:
            doc = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            return None
        keys: Dict[str, Dict[str, Any]] = {}
        for jwk in doc["keys"][:32]:
            if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            try:
                public_key_from_jwk(jwk)
                keys[jwk_thumbprint(jwk)] = jwk   # select by thumbprint we compute, never by label
            except (ValueError, KeyError, TypeError):
                continue
        if self.require_directory_signature:
            signed = directory_signed_keys(urllib.parse.urlsplit(url).netloc, headers, keys, now, self.max_skew)
            keys = {kid: jwk for kid, jwk in keys.items() if kid in signed}
        card = doc.get("agent_card") if isinstance(doc.get("agent_card"), dict) else {}
        max_age = _max_age(headers)
        ttl = self.cache_ttl if max_age is None else max(0, min(max_age, self.cache_ttl))
        return _Cached(keys, {k: card[k] for k in ("client_name", "client_uri", "contacts", "acts_for") if k in card},
                       now, ttl)

    def forget(self, url: str) -> None:
        with self._lock:
            self._cache.pop(normalize_agent_url(url), None)

    # -- verify ------------------------------------------------------------------------------
    def verify(self, method: str, path_and_query: str, headers: Mapping[str, str], body: bytes) -> Identity:
        h = {k.lower(): v for k, v in headers.items()}
        if "signature" not in h and "signature-input" not in h:
            return unsigned("no_signature")
        try:
            return self._verify(method, path_and_query, h, body or b"")
        except SFError as e:
            return rejected("malformed_signature_headers: %s" % e)

    def _verify(self, method: str, path_and_query: str, h: Dict[str, str], body: bytes) -> Identity:
        now = int(self.clock())
        inputs = parse_dictionary(h.get("signature-input", ""))
        sigs = parse_dictionary(h.get("signature", ""))
        label = next((lb for lb, (v, p) in inputs.items() if isinstance(v, list) and dict(p).get("tag") == TAG), None)
        if label is None:
            return rejected("no_web_bot_auth_signature")
        comps_raw, sp = inputs[label]
        params = dict(sp)
        sig_val = sigs.get(label, (None, []))[0]
        if not isinstance(sig_val, (bytes, bytearray)):
            return rejected("signature_missing_for_label")
        sig_hash = hashlib.sha256(bytes(sig_val)).hexdigest()
        comps: List[Component] = []
        for v, p in comps_raw:
            if not isinstance(v, str) or isinstance(v, Token):
                return rejected("bad_component")
            comps.append((v, list(p)))
        names = {(n, tuple(p)) for n, p in comps}

        # What we require covered (stricter than the draft's minimum, on purpose).
        if ("@authority", ()) not in names and ("@target-uri", ()) not in names:
            return rejected("authority_not_covered")
        if ("signature-agent", (("key", label),)) not in names:
            return rejected("signature_agent_not_covered")
        for need in ("@method", "@path"):
            if (need, ()) not in names and ("@target-uri", ()) not in names:
                return rejected("%s_not_covered" % need.strip("@"))
        if ("content-digest", ()) not in names:
            return rejected("body_not_covered")
        q = path_and_query.split("?", 1)
        if len(q) == 2 and q[1] and ("@query", ()) not in names and ("@target-uri", ()) not in names:
            return rejected("query_not_covered")

        created, expires = params.get("created"), params.get("expires")
        if not isinstance(created, int) or not isinstance(expires, int):
            return rejected("created_and_expires_required")
        if created > now + self.max_skew:
            return rejected("created_in_future")
        if expires < now - self.max_skew:
            return rejected("expired")
        if expires - created > self.max_lifetime or expires <= created:
            return rejected("lifetime_too_long")
        nonce = params.get("nonce")
        if self.require_nonce and (not isinstance(nonce, str) or len(nonce) < 16):
            return rejected("nonce_required")
        keyid = params.get("keyid")
        if not isinstance(keyid, str) or not keyid:
            return rejected("keyid_required")
        alg = params.get("alg")
        if alg is not None and alg != "ed25519":
            return rejected("unsupported_alg")

        if h.get("content-digest", "").strip() != content_digest(body):
            # Accept other sha-256 serialisations only if they decode to the same digest.
            try:
                d = parse_dictionary(h.get("content-digest", ""))
                got = d.get("sha-256", (None,))[0]
            except SFError:
                got = None
            if got != hashlib.sha256(body).digest():
                return rejected("body_digest_mismatch")

        agents = parse_dictionary(h.get("signature-agent", ""))
        member = agents.get(label)
        if member is None or not isinstance(member[0], str) or isinstance(member[0], Token) or member[1]:
            return rejected("signature_agent_member_invalid")
        agent_url = normalize_agent_url(member[0])
        bad = safe_https_url(agent_url)
        if bad:
            return rejected("signature_agent_url_refused: %s" % bad)
        u = urllib.parse.urlsplit(agent_url)
        domain = (u.hostname or "").lower()
        common = dict(agent_url=agent_url, domain="", keyid=keyid, created=created, expires=expires,
                      nonce=str(nonce or ""), signature_sha256=sig_hash)

        if agent_url in self.revoked_agents or keyid in self.revoked_keyids:
            return rejected("revoked_by_door", **common)

        d = self._directory(agent_url)
        if d is None:
            # Could not reach the claimed owner. Not proof of forgery, so not a 401, but no credit.
            return Identity(level=UNSIGNED, reason="directory_unreachable", **common)
        jwk = d.keys.get(keyid)
        if jwk is None:
            return rejected("key_not_published_by_claimed_owner", **common)
        nbf, exp = jwk.get("nbf"), jwk.get("exp")
        if isinstance(nbf, (int, float)) and now < nbf:
            return rejected("key_not_yet_valid", **common)
        if isinstance(exp, (int, float)) and now >= exp:
            return rejected("key_expired", **common)

        msg = Message(method.upper(), self.authority, q[0] or "/", q[1] if len(q) == 2 else "", h)
        try:
            base, _ = signature_base(msg, comps, sp)
        except SFError as e:
            return rejected("cannot_build_signature_base: %s" % e, **common)
        try:
            public_key_from_jwk(jwk).verify(bytes(sig_val), base)
        except InvalidSignature:
            return rejected("bad_signature", **common)

        if nonce is not None and not self.nonces.check_and_record(agent_url, str(nonce), expires + self.max_skew, now):
            return rejected("replayed", **common)

        well_known = u.path == WELL_KNOWN_PATH and not u.query
        level = DOMAIN_VERIFIED if well_known else SIGNED
        if level == DOMAIN_VERIFIED and domain in self.partners:
            level = PARTNER
        common["domain"] = domain if well_known else ""
        return Identity(level=level, reason="ok", card=dict(d.card), **common)


def normalize_agent_url(url: str) -> str:
    """Identifier form: scheme and host lowercased, default port and query dropped (draft 5.5)."""
    try:
        u = urllib.parse.urlsplit(str(url).strip())
    except ValueError:
        return str(url)
    host = (u.hostname or "").lower()
    netloc = host if u.port in (None, 443) else "%s:%s" % (host, u.port)
    return urllib.parse.urlunsplit((u.scheme.lower(), netloc, u.path or "/", "", ""))


def well_known_url(domain: str) -> str:
    return "https://%s%s" % (domain.lower(), WELL_KNOWN_PATH)


# ------------------------------------------------------------------------------ signed receipts
def receipt_payload(receipt: Mapping[str, Any]) -> bytes:
    """What a door signs: the receipt's own chain hash plus the fields a caller relies on."""
    keep = {k: receipt.get(k) for k in ("seq", "ts", "ask_id", "ask_type", "decision", "reason", "text_sha256",
                                        "prev", "hash", "identity", "verified_domain", "request_sig_sha256")
            if k in receipt}
    return json.dumps(keep, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_receipt(key: AgentKey, key_url: str, receipt: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(receipt)
    out["door_signature"] = {"alg": "ed25519", "keyid": key.keyid, "key_url": key_url,
                             "sig": b64url(key.sign(receipt_payload(receipt)))}
    return out


def verify_receipt(receipt: Mapping[str, Any], directory_doc: Mapping[str, Any]) -> bool:
    """Caller side: check a receipt the door signed, against the door's published key directory."""
    ds = receipt.get("door_signature") or {}
    for jwk in directory_doc.get("keys", []):
        try:
            if jwk_thumbprint(jwk) != ds.get("keyid"):
                continue
            public_key_from_jwk(jwk).verify(b64url_decode(ds["sig"]), receipt_payload(receipt))
            return True
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return False
    return False
