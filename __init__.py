"""hermes-consent-network: other people's agents may ask, your allow-list and you decide.

Inbound (``pre_gateway_dispatch`` on the a2a platform): every ask from a peer agent is matched
against that peer's YAML allow-list. Allowed asks reach the model with a consent banner. Denied
asks and asks waiting on the owner reach the model WITHOUT the request text, so the model cannot
act on what it never saw. An ask outside the allow-list becomes one question to the named owner
through ``hermes send``; the owner answers ``consent yes CODE`` / ``consent no CODE`` from any chat,
``/consent approve CODE`` or ``hermes consent approve CODE``. A no is remembered.

Outbound (``pre_tool_call`` / ``post_tool_call`` on a2a_call, a2a_orchestrate, message_agent):
asks must declare their type, hard-denied types are never sent, and both legs are receipted.

Every step writes a hash-chained receipt. Fails open for everything except the consent decision
itself: if the policy cannot be read, the ask is denied, not allowed.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from . import core

try:  # agent identity needs `cryptography` (Ed25519); without it the plugin runs exactly as before
    from . import identity as idm
except ImportError:  # pragma: no cover
    idm = None

log = logging.getLogger(__name__)
RANK = {"unsigned": 0, "signed": 1, "domain_verified": 2, "partner": 3}

OUTBOUND_TOOLS = frozenset({"a2a_call", "a2a_orchestrate", "message_agent"})
_PRIVACY_PREFIX = re.compile(r"^\s*\[A2A inbound[^\]]*\]\s*", re.S)
_STATE_RE = re.compile(r"^\[[^\]\n]*\u00b7\s*([a-z-]+)\]", re.M)
PENDING_CALL_MAX = 200


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _platform_of(source: Any) -> str:
    platform = getattr(source, "platform", None)
    return str(getattr(platform, "value", platform) or "").lower()


def hermes_send(target: str, text: str, timeout: float = 30.0) -> bool:
    """The existing notify path: ``hermes send -t <target> -q``. No shell; message on stdin."""
    exe = shutil.which("hermes")
    if not exe or not target:
        return False
    try:
        proc = subprocess.run([exe, "send", "-t", target, "-q", "-f", "-"], input=text, text=True,
                              capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("hermes-consent-network: notify failed: %s", type(exc).__name__)
        return False
    return proc.returncode == 0


class ConsentNetwork:
    """All behavior, with injectable config, notifier and clock so tests need no Hermes."""

    def __init__(self, get_config: Callable[[str, Any], Any], *, profile: str = "default",
                 notifier: Callable[[str, str], bool] = hermes_send, clock: Callable[[], float] = time.time):
        self._get_config = get_config
        self.profile = profile
        self._notify = notifier
        self._clock = clock
        self._calls: Dict[str, Dict[str, Any]] = {}  # outbound tool_call_id -> ask

    # -- config -----------------------------------------------------------------------------
    def _cfg(self, key: str, default: Any) -> Any:
        try:
            value = self._get_config(key, default)
        except Exception:
            return default
        return default if value is None else value

    def state_dir(self) -> Path:
        configured = self._cfg("state_dir", "")
        if isinstance(configured, str) and configured.strip():
            return Path(configured).expanduser()
        return core.default_state_dir()

    def peers_dir(self) -> Path:
        configured = self._cfg("peers_dir", "")
        if isinstance(configured, str) and configured.strip():
            return Path(configured).expanduser()
        return self.state_dir() / "peers"

    def receipts(self) -> core.Receipts:
        return core.Receipts(self.state_dir(), side=self.profile)

    def pending(self) -> core.Pending:
        return core.Pending(self.state_dir())

    def declines(self) -> core.Declines:
        return core.Declines(self.state_dir())

    def _owner_ids(self) -> set:
        raw = self._cfg("owner_ids", [])
        if isinstance(raw, str):
            raw = [raw]
        return {str(x).strip().lower() for x in raw if str(x).strip()} if isinstance(raw, (list, tuple)) else set()

    def _store_summary(self) -> bool:
        return core.coerce_bool(self._cfg("store_summary", True), True)

    def _ttl(self) -> float:
        return core.coerce_float(self._cfg("pending_ttl_hours", 24), 24) * 3600.0

    def _expire_days(self) -> float:
        return core.coerce_float(self._cfg("remember_no_days", 30), 30)

    def _threshold(self) -> float:
        return core.coerce_float(self._cfg("similarity", 0.6), 0.6)

    def _receipt(self, **fields: Any) -> None:
        try:
            if not self._store_summary():
                fields.pop("summary", None)
            self.receipts().append(self._clock(), **fields)
        except Exception as exc:  # a receipt failure must never decide an ask
            log.warning("hermes-consent-network: receipt not written: %s: %s", type(exc).__name__, exc)

    # -- inbound ----------------------------------------------------------------------------
    def pre_gateway_dispatch(self, event: Any = None, **_: Any) -> Optional[Dict[str, Any]]:
        try:
            source = getattr(event, "source", None)
            text = _text(getattr(event, "text", ""))
            platform = _platform_of(source)
            if platform == "a2a":
                peer = _text(getattr(source, "user_id", "")) or "unknown"
                # Set only by the transport that checked the HTTP signature (never parsed from the text).
                ident = getattr(event, "agent_identity", None) or getattr(source, "agent_identity", None)
                return self.inbound(peer, text, identity=ident)
            m = core.ANSWER_RE.match(text or "")
            if m and platform:
                who = "%s:%s" % (platform, _text(getattr(source, "user_id", "")).lower())
                if who in self._owner_ids():
                    yes = m.group("answer").lower() in ("yes", "approve")
                    reply = self.answer(m.group("code"), yes, via=platform)
                    self._notify_owner_ack(platform, reply)
                    return {"action": "skip", "reason": "consent answer recorded"}
        except Exception as exc:
            log.warning("hermes-consent-network pre_gateway_dispatch: %s: %s", type(exc).__name__, exc)
            if _platform_of(getattr(event, "source", None)) == "a2a":
                # The consent decision fails closed: an error here never lets an ask through.
                return {"action": "rewrite", "text": self._withheld("UNKNOWN", "unknown", "unknown",
                                                                     "denied", "consent check failed")}
        return None

    def _notify_owner_ack(self, platform: str, reply: str) -> None:
        target = str(self._cfg("owner_notify_to", "") or "")
        if target.split(":", 1)[0].lower() == platform:
            try:
                self._notify(target, reply)
            except Exception:
                pass

    @staticmethod
    def _banner(ask_id: str, peer: str, ask_type: str, owner: str, how: str) -> str:
        return ("[consent-network ask=%s peer=%s type=%s: ALLOWED (%s). Do only what this ask needs. "
                "Begin your reply with the line: consent: %s allowed]\n\n" % (ask_id, peer, ask_type, how, ask_id))

    @staticmethod
    def _withheld(ask_id: str, peer: str, ask_type: str, state: str, why: str) -> str:
        if state == "waiting":
            line = "[INPUT_REQUIRED] consent: %s waiting for the owner's approval. Re-send the same ask " \
                   "(same consent-ask id) later to get the answer." % ask_id
        else:
            line = "consent: %s denied (%s)" % (ask_id, why)
        return ("[consent-network ask=%s peer=%s type=%s: %s. The request text was withheld from you by "
                "the consent plugin. Take no action and call no tools for it. Reply with exactly this line "
                "and nothing else:]\n%s" % (ask_id, peer, ask_type, state.upper(), line))

    def _resolve_peer(self, a2a_peer: str, ident: Any):
        """(peer key, policy, level, identity receipt fields).

        A verified signature names the peer by its domain. The domain's own policy file wins; then the
        A2A credential's file; then the optional ``verified_default_policy`` file for any verified
        domain. Listed by name = partner; the default lane = domain_verified."""
        fields: Dict[str, Any] = {}
        domain = ""
        if idm is not None and isinstance(ident, idm.Identity):
            fields = {k: v for k, v in ident.receipt_fields().items()
                      if k in ("identity_label", "verified_domain", "signature_agent", "keyid", "request_sig_sha256")}
            if not ident.rejected and ident.level in (idm.DOMAIN_VERIFIED, idm.PARTNER):
                domain = ident.domain
        if a2a_peer and a2a_peer != "unknown":
            fields["a2a_peer"] = a2a_peer
        peers = self.peers_dir()
        if domain:
            pol = core.load_policy(peers, domain)
            if pol:
                return domain, pol, "partner", fields
        if a2a_peer and a2a_peer != "unknown":
            pol = core.load_policy(peers, a2a_peer)
            if pol:
                fields.setdefault("identity_label", "a2a credential: %s" % a2a_peer)
                return a2a_peer, pol, "partner", fields
        if domain:
            dflt = core.safe_name(self._cfg("verified_default_policy", ""))
            pol = core.load_policy(peers, dflt) if dflt else None
            return domain, pol, "domain_verified", fields
        return a2a_peer or "unknown", None, "unsigned", fields

    def inbound(self, peer: str, text: str, identity: Any = None) -> Dict[str, Any]:
        now = self._clock()
        body_full = _PRIVACY_PREFIX.sub("", text or "", count=1)
        ask_type, ask_id, body = core.parse_ask(body_full)
        a2a_peer = core.safe_name(peer) or "unknown"
        peer, policy, level, id_fields = self._resolve_peer(a2a_peer, identity)
        if not ask_id:
            ask_id = core.derived_ask_id(peer, ask_type, body)
        text_sha = core.sha256_text(core.normalize_text(body))
        summary = core.one_line(body)
        owner = policy.owner if policy else ""
        base = dict(direction="in", ask_id=ask_id, peer=peer, owner=owner, ask_type=ask_type, summary=summary,
                    text_sha256=text_sha, identity=level, **id_fields)

        def deny(reason: str, decided_by: str, event: str = "ask") -> Dict[str, Any]:
            self._receipt(event=event, decision="deny", reason=reason, decided_by=decided_by, **base)
            return {"action": "rewrite", "text": self._withheld(ask_id, peer, ask_type, "denied", reason)}

        def allow(reason: str, decided_by: str) -> Dict[str, Any]:
            self._receipt(event="ask", decision="allow", reason=reason, decided_by=decided_by, **base)
            how = "allow-list" if decided_by == "policy" else "approved by %s" % decided_by
            return {"action": "rewrite", "text": self._banner(ask_id, peer, ask_type, owner, how) + body}

        if idm is not None and isinstance(identity, idm.Identity) and identity.rejected:
            # A signature was presented and failed (forged, replayed, expired, wrong domain): refuse outright.
            return deny("signature_rejected:%s" % identity.reason.split(":")[0], "identity")
        if policy is None:
            return deny("no_policy_for_peer", "policy")
        need = policy.required_level(ask_type)
        if ask_type not in core.HARD_DENY and RANK.get(level, 0) < RANK.get(need, 99):
            return deny("needs_%s" % need, "identity")

        # An answer the owner already gave to this exact ask wins over everything except the hard floor.
        # The answer is bound to the ask's text hash: a peer cannot reuse an approved id for new words.
        pend = self.pending()
        pkey = "%s/%s" % (peer, ask_id)  # ask ids come from peers; never let two peers collide
        prior = pend.get(pkey)
        if prior is not None:
            owner_of = "owner:%s" % (prior.get("owner") or owner)
            if prior.get("peer") != peer or prior.get("text_sha256") != text_sha:
                return deny("ask_id_reused_with_different_text", "policy")
            status = prior.get("status")
            if ask_type in core.HARD_DENY:
                return deny("always_denied", "policy")
            if ask_type in policy.deny:
                return deny("peer_denied", "policy")
            if status == "approved":
                pend.set(pkey, status="used", used_at=now)
                return allow("owner_approved", owner_of)
            if status == "declined":
                return deny("owner_declined", owner_of)
            if status == "used":
                return deny("approval_already_used", "policy")
            if status == "pending" and now - float(prior.get("created", 0)) < self._ttl():
                self._receipt(event="ask", decision="ask_owner", reason="still_waiting", decided_by="policy", **base)
                return {"action": "rewrite", "text": self._withheld(ask_id, peer, ask_type, "waiting", "")}
            # an expired wait falls through and is asked again

        decision, reason = policy.decide(ask_type)
        if decision == core.DENY:
            return deny(reason, "policy")
        if decision == core.ALLOW:
            return allow(reason, "policy")

        hit = self.declines().match(peer=peer, ask_type=ask_type, body=body, threshold=self._threshold(),
                                    expire_days=self._expire_days(), now=now)
        if hit is not None:
            return deny("remembered_no", "remembered:%s:%s" % (hit.get("owner", owner), core.short_date(hit["ts"])))

        if pend.open_for_peer(peer, now, self._ttl()) >= policy.max_pending:
            return deny("too_many_open_asks", "policy")

        code = core.owner_code(ask_id, peer)
        record = {"key": pkey, "ask_id": ask_id, "peer": peer, "owner": owner, "ask_type": ask_type, "summary": summary,
                  "body": body[:2000], "text_sha256": text_sha, "code": code, "status": "pending",
                  "created": now, "reason": reason}
        if prior is None:
            pend.create(record)
        else:
            pend.set(pkey, **record)
        target = policy.notify_to or str(self._cfg("owner_notify_to", "") or "")
        question = ("%s's agent asks (%s): %s\nReply \"consent yes %s\" or \"consent no %s\"."
                    % (peer, ask_type, core.one_line(body, 200), code, code))
        notified = False
        try:
            notified = bool(self._notify(target, question))
        except Exception as exc:
            log.warning("hermes-consent-network: notify raised %s", type(exc).__name__)
        pend.set(pkey, notified=notified, notify_to=target)
        self._receipt(event="ask", decision="ask_owner", reason=reason, decided_by="policy",
                      detail={"owner_notified": notified, "code": code}, **base)
        return {"action": "rewrite", "text": self._withheld(ask_id, peer, ask_type, "waiting", "")}

    def answer(self, code: str, yes: bool, via: str = "cli") -> str:
        """The owner's answer to one waiting ask. A no is remembered."""
        pend = self.pending()
        rec = pend.by_code(code)
        if rec is None:
            return "No waiting ask has code %s. Try /consent pending." % (code or "").upper()
        if rec.get("status") != "pending":
            return "Ask %s was already answered (%s)." % (rec["ask_id"], rec.get("status"))
        now = self._clock()
        status = "approved" if yes else "declined"
        pend.set(rec.get("key") or rec["ask_id"], status=status, decided_at=now, decided_via=via)
        if not yes:
            self.declines().add(peer=rec["peer"], ask_type=rec["ask_type"], body=rec.get("body", ""),
                                ask_id=rec["ask_id"], owner=rec.get("owner", ""), now=now)
        self._receipt(event="owner_answer", direction="in", ask_id=rec["ask_id"], peer=rec["peer"],
                      owner=rec.get("owner", ""), ask_type=rec["ask_type"], text_sha256=rec.get("text_sha256"),
                      decision="approved" if yes else "declined", decided_by="owner:%s" % rec.get("owner", ""),
                      detail={"via": via})
        tail = "" if yes else " This no is remembered; the same ask from %s will be declined without asking you." % rec["peer"]
        return "%s %s's ask %s (%s).%s" % ("Approved" if yes else "Declined", rec["peer"], rec["ask_id"],
                                           rec["ask_type"], tail)

    def post_llm_call(self, user_message: Any = None, assistant_response: Any = None, platform: Any = None,
                      **_: Any) -> None:
        """Result receipt for an inbound ask: the model's reply, by hash and length only."""
        try:
            if str(platform or "").lower() != "a2a":
                return
            m = core.BANNER_RE.search(_text(user_message))
            if not m:
                return
            reply = _text(assistant_response)
            said = core.REPLY_RE.search(reply)
            self._receipt(event="result", direction="in", ask_id=m.group("id"), peer=m.group("peer"),
                          ask_type=m.group("type"), result="replied",
                          detail={"reply_sha256": core.sha256_text(reply), "reply_chars": len(reply),
                                  "reply_said": said.group("decision").lower() if said else ""})
        except Exception as exc:
            log.warning("hermes-consent-network post_llm_call: %s: %s", type(exc).__name__, exc)

    # -- outbound ---------------------------------------------------------------------------
    @staticmethod
    def _outbound_target(tool_name: str, args: Dict[str, Any]) -> str:
        if tool_name == "a2a_orchestrate":
            return "capability:%s" % _text(args.get("capability"))
        return _text(args.get("agent") or args.get("agent_name") or args.get("name") or args.get("to")
                     or args.get("target"))

    @staticmethod
    def _outbound_message(args: Dict[str, Any]) -> str:
        return _text(args.get("message") or args.get("text") or args.get("task") or args.get("content"))

    def pre_tool_call(self, tool_name: Any = None, args: Any = None, tool_call_id: Any = None,
                      **_: Any) -> Optional[Dict[str, Any]]:
        try:
            if tool_name not in OUTBOUND_TOOLS or not isinstance(args, dict):
                return None
            message = self._outbound_message(args)
            ask_type, ask_id, body = core.parse_ask(message)
            if core.coerce_bool(self._cfg("require_outbound_header", True), True) and ask_type == "unspecified":
                return {"action": "block", "message": (
                    "hermes-consent-network: an ask to another person's agent must declare its type. Put this "
                    "line first in the message, then send again:\n%s\n(<type> is one word such as "
                    "status_question or site_edit.)" % core.ask_header("<type>", core.new_ask_id()))}
            if ask_type in core.HARD_DENY:
                self._receipt(event="ask", direction="out", ask_id=ask_id or "-", peer=self._outbound_target(tool_name, args),
                              ask_type=ask_type, decision="deny", reason="always_denied", decided_by="policy")
                return {"action": "block", "message": (
                    "hermes-consent-network: '%s' asks are never sent agent-to-agent (money, prices, third-party "
                    "sends and deletions stay with the people). Tell your owner instead." % ask_type)}
            if not ask_id:
                return {"action": "block", "message": (
                    "hermes-consent-network: add an id to the consent-ask line so both sides can match receipts, "
                    "for example:\n%s" % core.ask_header(ask_type, core.new_ask_id()))}
            peer = self._outbound_target(tool_name, args)
            self._receipt(event="ask", direction="out", ask_id=ask_id, peer=peer, ask_type=ask_type,
                          summary=core.one_line(body), text_sha256=core.sha256_text(core.normalize_text(body)),
                          decision="sent", decided_by="agent:%s" % self.profile)
            if _text(tool_call_id):
                if len(self._calls) >= PENDING_CALL_MAX:
                    self._calls.pop(next(iter(self._calls)))
                self._calls[_text(tool_call_id)] = {"ask_id": ask_id, "peer": peer, "ask_type": ask_type}
        except Exception as exc:
            log.warning("hermes-consent-network pre_tool_call: %s: %s", type(exc).__name__, exc)
        return None

    def post_tool_call(self, tool_name: Any = None, args: Any = None, result: Any = None, tool_call_id: Any = None,
                       **_: Any) -> None:
        try:
            if tool_name not in OUTBOUND_TOOLS or not isinstance(args, dict):
                return
            info = self._calls.pop(_text(tool_call_id), None)
            if info is None:
                ask_type, ask_id, _body = core.parse_ask(self._outbound_message(args))
                if not ask_id:
                    return
                info = {"ask_id": ask_id, "peer": self._outbound_target(tool_name, args), "ask_type": ask_type}
            out = _text(result) if not isinstance(result, (dict, list)) else str(result)
            said = core.REPLY_RE.search(out)
            state = _STATE_RE.search(out)
            if out.startswith("Error"):
                outcome = "error"
            else:
                outcome = state.group(1) if state else "completed"
            peer_decision = said.group("decision").lower() if said and said.group("id").upper() == info["ask_id"] else ""
            self._receipt(event="result", direction="out", ask_id=info["ask_id"], peer=info["peer"],
                          ask_type=info["ask_type"], result=outcome,
                          detail={"peer_decision": peer_decision, "reply_sha256": core.sha256_text(out)})
        except Exception as exc:
            log.warning("hermes-consent-network post_tool_call: %s: %s", type(exc).__name__, exc)

    # -- /consent ---------------------------------------------------------------------------
    def command(self, raw_args: str = "") -> str:
        from . import cli
        try:
            return cli.run_text(self, (raw_args or "").split())
        except Exception as exc:
            log.warning("hermes-consent-network /consent: %s: %s", type(exc).__name__, exc)
            return "hermes-consent-network could not run that command (see the Hermes log)."


def register(ctx) -> None:
    from . import cli

    def get_config(key, default=None):
        getter = getattr(ctx, "get_config", None)
        return getter(key, default) if callable(getter) else default

    home = core.hermes_home()
    profile = str(get_config("side_name", "") or "") or (home.name if home.parent.name == "profiles" else "default")
    plugin = ConsentNetwork(get_config, profile=profile)
    ctx.register_hook("pre_gateway_dispatch", plugin.pre_gateway_dispatch)
    ctx.register_hook("post_llm_call", plugin.post_llm_call)
    ctx.register_hook("pre_tool_call", plugin.pre_tool_call)
    ctx.register_hook("post_tool_call", plugin.post_tool_call)
    ctx.register_command("consent", plugin.command,
                         description="Agent-to-agent consent: pending asks, approve/deny, receipts",
                         args_hint="pending | approve <code> | deny <code> | receipts | verify | declines")
    ctx.register_cli_command("consent", "Agent-to-agent consent: receipts, pending asks, answers",
                             cli.setup_parser, lambda args: cli.handle(plugin, args),
                             description="Read hash-chained consent receipts and answer waiting asks.")
