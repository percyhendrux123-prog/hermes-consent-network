"""hermes-consent-network core: ask parsing, per-peer policy, pending asks, remembered no's,
and the hash-chained receipt log. Stdlib only (PyYAML is used when importable).

Nothing here talks to the network or to Hermes. The hooks in __init__.py wire it up.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

DAY = 86400.0
GENESIS = "0" * 64
SUMMARY_MAX = 120

# Ask types no allow-list can open. A peer's agent may never move money, change prices,
# send to a third party, or delete data through this door. The owner can still do these
# things themselves; they just can't be asked for agent-to-agent.
HARD_DENY = frozenset({"money", "payment", "refund", "price", "pricing", "send_third_party",
                       "delete_data"})

# Decisions written to receipts.
ALLOW, DENY, ASK_OWNER = "allow", "deny", "ask_owner"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_TYPE_OK = re.compile(r"^[a-z0-9][a-z0-9_]{0,47}$")
# "consent-ask: site_edit id=AB12CD34" on its own line, optional surrounding brackets.
ASK_RE = re.compile(r"^[ \t]*\[?consent-ask[ \t]*:?[ \t]*(?P<type>[A-Za-z0-9_.-]+)"
                    r"(?:[ \t]+id=(?P<id>[A-Za-z0-9_-]{4,64}))?[ \t]*\]?[ \t]*$", re.M | re.I)
# The line a receiving agent is told to start its reply with.
REPLY_RE = re.compile(r"consent:[ \t]*(?P<id>[A-Za-z0-9_-]{4,64})[ \t]+(?P<decision>allowed|denied|waiting|duplicate)\b",
                      re.I)
# Owner answer through any chat surface: "consent yes K7Q2XM" / "consent no K7Q2XM".
ANSWER_RE = re.compile(r"^\s*consent\s+(?P<answer>yes|no|approve|deny)\s+(?P<code>[A-Za-z0-9]{6})\s*[.!]?\s*$",
                       re.I)
# Marker the plugin puts in front of every inbound ask it lets the model see.
BANNER_RE = re.compile(r"\[consent-network ask=(?P<id>[A-Za-z0-9_-]{4,64}) peer=(?P<peer>\S+) type=(?P<type>[a-z0-9_]+)")


# -- small helpers ---------------------------------------------------------------------------
def now_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_date(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def safe_name(value: Any) -> str:
    """A peer or profile name usable as a file name, or "" when it isn't one."""
    value = str(value or "").strip()
    return value if _SAFE_NAME.match(value) else ""


def normalize_type(value: Any) -> str:
    t = str(value or "").strip().lower().replace("-", "_").replace(".", "_")
    return t if _TYPE_OK.match(t) else ""


def normalize_text(text: Any) -> str:
    text = str(text or "").lower()
    text = re.sub(r"[^a-z0-9 ]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def jaccard(a: str, b: str) -> float:
    sa, sb = set(a.split()), set(b.split())
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / float(len(sa | sb) or 1)


def one_line(text: Any, limit: int = SUMMARY_MAX) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    return (cut.rsplit(" ", 1)[0] if " " in cut else cut) + "\u2026"


def new_ask_id() -> str:
    return secrets.token_hex(4).upper()


def owner_code(ask_id: str, peer: str, *, generation: str) -> str:
    """Six characters for this pending generation, not for all resends of this ask."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    digest = hashlib.sha256(("%s\0%s\0%s" % (peer, ask_id, generation)).encode()).digest()
    return "".join(alphabet[b % len(alphabet)] for b in digest[:6])


def coerce_float(value: Any, default: float) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if f >= 0 else default


def coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "yes", "on", "1"):
        return True
    if isinstance(value, str) and value.strip().lower() in ("false", "no", "off", "0"):
        return False
    return default


def hermes_home() -> Path:
    env = os.environ.get("HERMES_HOME")
    return Path(env).expanduser() if env else Path.home() / ".hermes"


def default_state_dir() -> Path:
    return hermes_home() / "plugins-state" / "hermes-consent-network"


# -- parsing an ask --------------------------------------------------------------------------
def parse_ask(text: str) -> Tuple[str, str, str]:
    """(ask_type, ask_id, body). Missing header -> ("unspecified", "", text)."""
    text = text or ""
    m = ASK_RE.search(text)
    if not m:
        return "unspecified", "", text.strip()
    ask_type = normalize_type(m.group("type")) or "unspecified"
    ask_id = m.group("id") or ""
    body = (text[:m.start()] + text[m.end():]).strip()
    return ask_type, ask_id.upper(), body


def ask_header(ask_type: str, ask_id: str) -> str:
    return "consent-ask: %s id=%s" % (ask_type, ask_id)


def derived_ask_id(peer: str, ask_type: str, body: str) -> str:
    return sha256_text("%s\0%s\0%s" % (peer, ask_type, normalize_text(body)))[:10].upper()


# -- policy files ----------------------------------------------------------------------------
def _scalar(raw: str) -> Any:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    low = raw.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    return raw


def mini_yaml(text: str) -> Dict[str, Any]:
    """The YAML subset a peer policy needs: top-level ``key: value``, ``key: [a, b]`` and
    ``key:`` followed by ``- item`` lines. Used only when PyYAML is not importable."""
    out: Dict[str, Any] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        stripped = line.split(" #", 1)[0].rstrip() if not line.lstrip().startswith("#") else ""
        if not stripped.strip():
            continue
        if stripped.lstrip().startswith("- ") and current is not None:
            if not isinstance(out.get(current), list):
                out[current] = []
            out[current].append(_scalar(stripped.lstrip()[2:]))
            continue
        if ":" not in stripped or stripped.startswith((" ", "\t")):
            continue
        key, _, value = stripped.partition(":")
        key, value = key.strip(), value.strip()
        current = key
        if value.startswith("[") and value.endswith("]"):
            out[key] = [_scalar(v) for v in value[1:-1].split(",") if v.strip()]
        elif value:
            out[key] = _scalar(value)
        else:
            out[key] = None
    return out


def load_yaml_text(text: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception:
        return mini_yaml(text)
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else {}


def _type_set(value: Any) -> frozenset:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return frozenset()
    return frozenset(t for t in (normalize_type(v) for v in value) if t)


class Policy:
    """One peer's rules, from ``<peers_dir>/<peer>.yaml``."""

    def __init__(self, peer: str, data: Dict[str, Any], source: str = ""):
        self.peer = peer
        self.source = source
        self.owner = str(data.get("owner") or "owner").strip() or "owner"
        self.notify_to = str(data.get("notify_to") or "").strip()
        self.allow = _type_set(data.get("allow"))
        self.deny = _type_set(data.get("deny"))
        self.ask_owner = _type_set(data.get("ask_owner"))
        self.max_pending = int(coerce_float(data.get("max_pending"), 3) or 3)
        # Trust floor per ask type (identity.py levels): unsigned < signed < domain_verified < partner.
        # A partner is a peer the owner listed by name: an A2A token peer with a policy file, or a
        # signature-verified domain with its own peers/<domain>.yaml.
        self.require_partner = _type_set(data.get("require_partner"))
        self.require_domain_verified = _type_set(data.get("require_domain_verified"))

    def required_level(self, ask_type: str) -> str:
        if ask_type in self.require_partner:
            return "partner"
        if ask_type in self.require_domain_verified:
            return "domain_verified"
        return "unsigned"

    def decide(self, ask_type: str) -> Tuple[str, str]:
        """(decision, reason). Order: hard floor, peer deny, allow, everything else to the owner."""
        if ask_type in HARD_DENY:
            return DENY, "always_denied"
        if ask_type in self.deny:
            return DENY, "peer_denied"
        if ask_type in self.allow:
            return ALLOW, "allow_list"
        if ask_type in self.ask_owner:
            return ASK_OWNER, "listed_for_owner"
        return ASK_OWNER, "unknown_type"


def load_policy(peers_dir: Path, peer: str) -> Optional[Policy]:
    """The peer's policy, or None (no file, unsafe name, unreadable, or symlinked)."""
    name = safe_name(peer)
    if not name:
        return None
    for suffix in (".yaml", ".yml"):
        path = Path(peers_dir) / (name + suffix)
        if path.is_symlink() or not path.is_file():
            continue
        try:
            data = load_yaml_text(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        declared = safe_name(data.get("peer")) if data.get("peer") is not None else name
        if declared != name:
            return None  # a file that names a different peer is not this peer's consent
        return Policy(name, data, str(path))
    return None


# -- locked JSON state (pending asks, remembered no's) -----------------------------------------
def _ensure_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise OSError("refusing symlinked state dir %s" % path)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


class _FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd = -1

    def __enter__(self):
        _ensure_dir(self.path.parent)
        self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(self.fd, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
        return False


class JsonState:
    """A dict in one 0600 JSON file, read-modify-written under an flock."""

    def __init__(self, path: Path, *, validate: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.path = Path(path)
        self.lock = self.path.with_suffix(".lock")
        self.validate = validate

    def _read(self) -> Dict[str, Any]:
        if self.path.is_symlink():
            raise OSError("refusing symlinked state file %s" % self.path)
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (ValueError, OSError):
            if self.validate is not None:
                raise
            bad = "%s.corrupt-%d" % (self.path, int(time.time()))
            try:
                os.replace(self.path, bad)
            except OSError:
                pass
            return {}
        if isinstance(data, dict):
            if self.validate is not None:
                self.validate(data)
            return data
        if self.validate is not None:
            raise ValueError("state must be an object")
        return {}

    def _write(self, data: Dict[str, Any]) -> None:
        tmp = "%s.tmp-%s" % (self.path, uuid.uuid4().hex[:8])
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def read(self) -> Dict[str, Any]:
        with _FileLock(self.lock):
            return self._read()

    def update(self, fn: Callable[[Dict[str, Any]], Any]) -> Any:
        with _FileLock(self.lock):
            data = self._read()
            result = fn(data)
            self._write(data)
            return result


class Pending:
    """Owner decisions and short-lived allow-list claims, keyed by peer and ask ID."""

    def __init__(self, state_dir: Path):
        self.state = JsonState(Path(state_dir) / "pending.json", validate=self._validate)

    @staticmethod
    def _validate(data: Dict[str, Any]) -> None:
        asks = data.get("asks", {})
        if not isinstance(asks, dict):
            raise ValueError("pending asks must be an object")
        for rec in asks.values():
            if not isinstance(rec, dict) or rec.get("status") not in ("pending", "approved", "declined", "used", "allowed"):
                raise ValueError("malformed pending record")
            if any(not isinstance(rec.get(field), str) for field in ("peer", "ask_id", "ask_type")):
                raise ValueError("malformed pending binding")
            if rec["status"] == "allowed":
                if type(rec.get("expires_at")) not in (int, float) or not isinstance(rec.get("request_sha256"), str):
                    raise ValueError("malformed allow-list claim")
            elif type(rec.get("created")) not in (int, float) or not isinstance(rec.get("code"), str):
                raise ValueError("malformed pending owner decision")

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return (self.state.read().get("asks") or {}).get(key)

    def all(self) -> List[Dict[str, Any]]:
        return list((self.state.read().get("asks") or {}).values())

    def open_for_peer(self, peer: str, now: float, ttl: float) -> int:
        return sum(1 for r in self.all() if r.get("peer") == peer and r.get("status") == "pending"
                   and now - float(r.get("created", 0)) < ttl)

    def set(self, _key: str, **fields: Any) -> Optional[Dict[str, Any]]:
        def fn(data):
            rec = (data.get("asks") or {}).get(_key)
            if rec is not None:
                rec.update(fields)
            return rec
        return self.state.update(fn)

    @staticmethod
    def replay_expired(rec: Dict[str, Any], now: float) -> bool:
        return rec.get("status") == "allowed" and now >= rec["expires_at"]

    def replace(self, key: str, before: Optional[Dict[str, Any]], after: Dict[str, Any], *,
                replay_window: Optional[Tuple[Callable[[], float], float]] = None,
                guard: Optional[Callable[[], bool]] = None) -> bool:
        """Commit a decision only if the record inspected by the caller is still current."""
        def fn(data):
            asks = data.setdefault("asks", {})
            expected = before
            replacement = after
            if replay_window is not None:
                clock, ttl = replay_window
                prune_at = clock()
                for old_key, old in list(asks.items()):
                    if self.replay_expired(old, prune_at):
                        del asks[old_key]
                if expected is not None and self.replay_expired(expected, prune_at):
                    expected = None
                if after.get("status") == "allowed":
                    replacement = dict(after, expires_at=prune_at + ttl)
            if asks.get(key) != expected or (guard is not None and not guard()):
                return False
            asks[key] = replacement
            return True
        return self.state.update(fn)

    def by_code(self, code: str) -> Optional[Dict[str, Any]]:
        code = (code or "").strip().upper()
        hits = [r for r in self.all() if r.get("code") == code]
        return hits[0] if len(hits) == 1 else None

    def drop(self, key: str) -> None:
        self.state.update(lambda data: (data.get("asks") or {}).pop(key, None))


class Declines:
    """Remembered no's (the hermes-declines pattern, keyed by peer + ask type + wording)."""

    def __init__(self, state_dir: Path):
        self.state = JsonState(Path(state_dir) / "declines.json")

    def add(self, *, peer: str, ask_type: str, body: str, ask_id: str, owner: str, now: float) -> Dict[str, Any]:
        rec = {"id": uuid.uuid4().hex[:8], "peer": peer, "ask_type": ask_type, "text": normalize_text(body)[:400],
               "text_sha256": sha256_text(normalize_text(body)), "ask_id": ask_id, "owner": owner, "ts": now}
        self.state.update(lambda data: data.setdefault("declines", []).append(rec))
        return rec

    def active(self, expire_days: float, now: float) -> List[Dict[str, Any]]:
        rows = [r for r in (self.state.read().get("declines") or []) if isinstance(r, dict)]
        if expire_days <= 0:
            return []
        return [r for r in rows if now - float(r.get("ts", 0)) < expire_days * DAY]

    def match(self, *, peer: str, ask_type: str, body: str, threshold: float, expire_days: float,
              now: float) -> Optional[Dict[str, Any]]:
        text = normalize_text(body)
        best, best_score = None, -1.0
        for r in self.active(expire_days, now):
            if r.get("peer") != peer or r.get("ask_type") != ask_type:
                continue
            score = 1.0 if r.get("text_sha256") == sha256_text(text) else jaccard(r.get("text", ""), text[:400])
            if score >= threshold and score > best_score:
                best, best_score = r, score
        return best

    def forget(self, ident: str) -> Optional[Dict[str, Any]]:
        def fn(data):
            rows = data.get("declines") or []
            hits = [r for r in rows if str(r.get("id", "")).startswith(ident)]
            if len(hits) != 1:
                return None
            rows.remove(hits[0])
            return hits[0]
        return self.state.update(fn) if ident else None


# -- receipts -------------------------------------------------------------------------------
RECEIPT_FIELDS = ("v", "seq", "ts", "side", "direction", "event", "ask_id", "peer", "owner", "ask_type",
                  "summary", "text_sha256", "decision", "reason", "decided_by", "result", "detail",
                  # agent identity (identity.py): who stands behind the peer, and the peer's signature hash
                  "identity", "identity_label", "a2a_peer", "verified_domain", "signature_agent", "keyid",
                  "request_sig_sha256")


def _canonical(rec: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def receipt_hash(rec: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(rec)).hexdigest()


class Receipts:
    """Append-only, hash-chained JSONL. Each line carries ``seq``, ``prev`` (the hash of the line
    before, or 64 zeros) and ``hash`` (sha256 of the canonical JSON of every other field)."""

    def __init__(self, state_dir: Path, side: str = ""):
        self.dir = Path(state_dir)
        self.path = self.dir / "receipts.jsonl"
        self.lock = self.dir / "receipts.lock"
        self.side = side

    def _tail(self) -> Tuple[int, str]:
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 65536))
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        except FileNotFoundError:
            return 0, GENESIS
        if not lines:
            return 0, GENESIS
        last = json.loads(lines[-1].decode("utf-8"))
        return int(last["seq"]), str(last["hash"])

    def append(self, now: float, *, signer: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
               **fields: Any) -> Dict[str, Any]:
        with _FileLock(self.lock):
            if self.path.is_symlink():
                raise OSError("refusing symlinked receipts file %s" % self.path)
            seq, prev = self._tail()
            rec: Dict[str, Any] = {"v": 1, "seq": seq + 1, "ts": now_iso(now), "side": self.side}
            for key in RECEIPT_FIELDS:
                if key in fields and fields[key] not in (None, ""):
                    rec[key] = fields[key]
            rec["prev"] = prev
            if signer is not None:
                rec = signer(rec)
            rec["hash"] = receipt_hash(rec)
            fd = os.open(str(self.path), os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, (json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            return rec

    def read(self) -> List[Dict[str, Any]]:
        return read_receipts(self.path)


def read_receipts(path: Path) -> List[Dict[str, Any]]:
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if not isinstance(rec, dict):
                        raise ValueError("receipt must be an object")
                    out.append(rec)
                except ValueError:
                    out.append({"_unparseable": line[:80]})
    except FileNotFoundError:
        pass
    return out


def verify_chain(records: Iterable[Dict[str, Any]]) -> Tuple[bool, int, List[str]]:
    """(ok, count, problems). Checks each line's own hash, its link to the line before and that
    seq counts up by one from 1. An edit, deletion, reorder or insertion breaks at least one."""
    problems: List[str] = []
    prev, expected_seq, count = GENESIS, 1, 0
    for rec in records:
        count += 1
        if "_unparseable" in rec:
            problems.append("line %d: not JSON" % count)
            prev, expected_seq = "", expected_seq + 1
            continue
        seq = rec.get("seq")
        if seq != expected_seq:
            problems.append("line %d: seq %r, expected %d" % (count, seq, expected_seq))
        if rec.get("prev") != prev:
            problems.append("line %d (seq %r): prev hash does not match the line before" % (count, seq))
        if rec.get("hash") != receipt_hash(rec):
            problems.append("line %d (seq %r): content does not match its hash" % (count, seq))
        prev = str(rec.get("hash", ""))
        expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1
    return not problems, count, problems


def final_decisions(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Per ask id: type, text hash, last decision and last available reply hash."""
    out: Dict[str, Dict[str, Any]] = {}
    for r in records:
        ask_id = r.get("ask_id")
        if not ask_id:
            continue
        cur = out.setdefault(ask_id, {})
        if r.get("peer") and r.get("direction"):
            cur.setdefault("scopes", set()).add((r["peer"], r["direction"]))
        for key in ("ask_type", "text_sha256"):
            if r.get(key):
                cur.setdefault(key, r[key])
        if r.get("decision"):
            cur["decision"] = r["decision"]
        if r.get("event") == "result" and r.get("detail") and isinstance(r["detail"], dict):
            peer_decision = r["detail"].get("peer_decision")
            if peer_decision:
                cur["decision"] = peer_decision
            reply_sha = r["detail"].get("reply_sha256")
            # A duplicate acknowledges the original decision; it isn't a new answer to the ask.
            if reply_sha and r.get("result") != "duplicate" and peer_decision != "duplicate":
                cur["reply_sha256"] = reply_sha
                cur["reply_phase"] = _SAME.get(peer_decision or r["detail"].get("reply_said"), "")
    return out


# Both sides' words for the same outcome.
_SAME = {"allow": "allowed", "allowed": "allowed", "approved": "allowed", "duplicate": "allowed",
         "deny": "denied", "denied": "denied",
         "declined": "denied", "remembered_no": "denied", "ask_owner": "waiting", "waiting": "waiting"}


def _comparison_rows(records: List[Dict[str, Any]], label: str, *, check_signatures: bool = False,
                     directory: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], List[str]]:
    rows, issues = [], []
    for line, receipt in enumerate(records, 1):
        row_label = "%s receipt line %d" % (label, line)
        if not isinstance(receipt, dict) or "_unparseable" in receipt:
            issues.append("%s: malformed receipt" % row_label)
            continue
        detail = receipt.get("detail", {})
        if (any(not isinstance(receipt[k], str)
                for k in ("ask_id", "peer", "direction", "ask_type", "decision", "text_sha256") if k in receipt)
                or not isinstance(detail, dict)
                or any(not isinstance(detail[k], str)
                       for k in ("peer_decision", "reply_said", "reply_sha256") if k in detail)):
            issues.append("%s: malformed comparison fields" % row_label)
            continue
        if check_signatures and "door_signature" in receipt:
            if directory is None:
                issues.append("%s: signature not verified (no trusted peer key directory)" % row_label)
                continue
            try:
                from .identity import verify_receipt
            except ImportError:
                issues.append("%s: signature not verified (cryptography unavailable)" % row_label)
                continue
            if not verify_receipt(receipt, directory):
                issues.append("%s: invalid receipt signature" % row_label)
                continue
            if receipt.get("hash") != receipt_hash(receipt):
                issues.append("%s: signed receipt hash does not match its contents" % row_label)
                continue
        rows.append(receipt)
    return rows, issues


def compare_report(mine: List[Dict[str, Any]], theirs: List[Dict[str, Any]], *,
                   peer_directory: Optional[Dict[str, Any]] = None) -> Tuple[int, List[str], List[str]]:
    """Compare a pair of ledgers. Invalid peer signatures are issues, not evidence."""
    mine, my_issues = _comparison_rows(mine, "local")
    theirs, peer_issues = _comparison_rows(theirs, "peer", check_signatures=True, directory=peer_directory)
    a, b = final_decisions(mine), final_decisions(theirs)
    shared = sorted(set(a) & set(b))
    issues, notes = my_issues + peer_issues, []
    compared = 0
    for ask_id in shared:
        x, y = a[ask_id], b[ask_id]
        xs, ys = x.get("scopes", ()), y.get("scopes", ())
        if len(xs) > 1 or len(ys) > 1:
            issues.append("%s: ambiguous ask ID across peers or directions; not compared" % ask_id)
            continue
        if xs and ys and {next(iter(xs))[1], next(iter(ys))[1]} != {"in", "out"}:
            issues.append("%s: receipt directions are not reciprocal; not compared" % ask_id)
            continue
        compared += 1
        if x.get("ask_type") and y.get("ask_type") and x["ask_type"] != y["ask_type"]:
            issues.append("%s: ask type %s vs %s" % (ask_id, x["ask_type"], y["ask_type"]))
        if x.get("text_sha256") and y.get("text_sha256") and x["text_sha256"] != y["text_sha256"]:
            issues.append("%s: the two sides hashed different ask text" % ask_id)
        px, py = x.get("reply_phase"), y.get("reply_phase")
        different_phase = (px == "waiting") != (py == "waiting")
        if (not different_phase and x.get("reply_sha256") and y.get("reply_sha256")
                and x["reply_sha256"] != y["reply_sha256"]):
            issues.append("%s: the two sides hashed different replies" % ask_id)
        dx, dy = _SAME.get(x.get("decision", ""), ""), _SAME.get(y.get("decision", ""), "")
        if dx != dy and "waiting" in (dx, dy):
            notes.append("%s: one side is %s, the other last saw waiting (answer not yet collected)"
                         % (ask_id, (dx if dy == "waiting" else dy) or "unknown"))
        elif dx and dy and dx != dy:
            issues.append("%s: decision %s vs %s" % (ask_id, dx, dy))
    unsigned = sum("door_signature" not in r and bool(r.get("ask_id")) for r in theirs)
    if unsigned:
        notes.append("%d peer receipt(s) unsigned; accepted for comparison without signature verification" % unsigned)
    return compared, issues, notes


def compare_sides(mine: List[Dict[str, Any]], theirs: List[Dict[str, Any]], *,
                  peer_directory: Optional[Dict[str, Any]] = None) -> Tuple[int, List[str]]:
    shared, issues, _ = compare_report(mine, theirs, peer_directory=peer_directory)
    return shared, issues


def compare_notes(mine: List[Dict[str, Any]], theirs: List[Dict[str, Any]], *,
                  peer_directory: Optional[Dict[str, Any]] = None) -> List[str]:
    return compare_report(mine, theirs, peer_directory=peer_directory)[2]
