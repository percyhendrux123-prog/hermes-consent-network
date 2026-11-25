"""``hermes consent ...`` and ``/consent ...``: one set of subcommands, two front doors."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, List

from . import core

USAGE = ("Usage: consent pending | approve <code> | deny <code> | receipts [--ask ID] [--peer NAME] "
         "[--last N] [--json] | verify [path] | compare <other receipts.jsonl> [--peer-directory <json>] | declines | "
         "forget <decline id> | policy <peer>")


def setup_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="consent_cmd")
    sub.add_parser("pending", help="Asks waiting on the owner")
    for name, helptext in (("approve", "Approve one waiting ask"), ("deny", "Decline one waiting ask (remembered)")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("code")
    r = sub.add_parser("receipts", help="Show consent receipts")
    r.add_argument("--ask", default="")
    r.add_argument("--peer", default="")
    r.add_argument("--last", type=int, default=20)
    r.add_argument("--json", action="store_true")
    r.add_argument("--path", default="", help="Read another receipts.jsonl instead of this profile's")
    v = sub.add_parser("verify", help="Check the receipt hash chain")
    v.add_argument("path", nargs="?", default="")
    c = sub.add_parser("compare", help="Cross-check this side's receipts with the other side's file")
    c.add_argument("other")
    c.add_argument("--mine", default="")
    c.add_argument("--peer-directory", default="", help="Trusted local JSON public key directory of the peer")
    sub.add_parser("declines", help="Remembered no's")
    f = sub.add_parser("forget", help="Forget one remembered no")
    f.add_argument("decline_id")
    pol = sub.add_parser("policy", help="Show what a peer may ask")
    pol.add_argument("peer")


def handle(plugin: Any, args: argparse.Namespace) -> int:
    argv: List[str] = [args.consent_cmd or ""]
    cmd = args.consent_cmd
    if cmd in ("approve", "deny"):
        argv.append(args.code)
    elif cmd == "receipts":
        argv += ["--last", str(args.last)]
        if args.ask:
            argv += ["--ask", args.ask]
        if args.peer:
            argv += ["--peer", args.peer]
        if args.json:
            argv.append("--json")
        if args.path:
            argv += ["--path", args.path]
    elif cmd == "verify" and args.path:
        argv.append(args.path)
    elif cmd == "compare":
        argv.append(args.other)
        if args.mine:
            argv += ["--mine", args.mine]
        if args.peer_directory:
            argv += ["--peer-directory", args.peer_directory]
    elif cmd == "forget":
        argv.append(args.decline_id)
    elif cmd == "policy":
        argv.append(args.peer)
    out = run_text(plugin, argv, via="cli")
    print(out)
    return 1 if out.startswith(("BROKEN", "MISMATCH")) else 0


def _opt(argv: List[str], name: str, default: str = "") -> str:
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


def format_receipt(r: dict) -> str:
    if "_unparseable" in r:
        return "  ?    unparseable line"
    who = r.get("decided_by", "")
    bits = [str(r.get("seq", "?")).rjust(4), r.get("ts", "")[11:20], r.get("side", "") + ":",
            {"in": "<-", "out": "->"}.get(r.get("direction", ""), "  "), r.get("peer", "-"),
            r.get("ask_id", "-"), r.get("event", ""), r.get("ask_type", "")]
    if r.get("decision"):
        bits.append("decision=" + r["decision"])
    if r.get("reason"):
        bits.append("(" + r["reason"] + ")")
    if who:
        bits.append("by=" + who)
    if r.get("result"):
        bits.append("result=" + r["result"])
    detail = r.get("detail") if isinstance(r.get("detail"), dict) else {}
    if detail.get("peer_decision"):
        bits.append("peer_said=" + detail["peer_decision"])
    if detail.get("reply_said"):
        bits.append("reply_said=" + detail["reply_said"])
    if r.get("summary") and r.get("event") == "ask":
        bits.append('"%s"' % core.one_line(r["summary"], 60))
    return " ".join(b for b in bits if b)


def run_text(plugin: Any, argv: List[str], via: str = "slash") -> str:
    sub = (argv[0] if argv else "pending").lower() or "pending"
    rest = argv[1:]
    if sub == "pending":
        rows = [r for r in plugin.pending().all() if r.get("status") == "pending"]
        if not rows:
            return "No asks are waiting on you."
        lines = ["Waiting on you:"]
        for r in sorted(rows, key=lambda r: r.get("created", 0)):
            lines.append("  %s  %s asks (%s, ask %s): %s" % (r.get("code"), r.get("peer"), r.get("ask_type"), r.get("ask_id"),
                                                     core.one_line(r.get("summary", ""), 80)))
        lines.append("Answer with: consent approve <code>  or  consent deny <code>")
        return "\n".join(lines)
    if sub in ("approve", "yes", "deny", "no"):
        if len(rest) != 1:
            return "Usage: consent %s <code>" % sub
        return plugin.answer(rest[0], sub in ("approve", "yes"), via=via)
    if sub == "receipts":
        path = Path(_opt(rest, "--path")) if _opt(rest, "--path") else plugin.receipts().path
        rows = core.read_receipts(path)
        ask, peer = _opt(rest, "--ask").upper(), _opt(rest, "--peer")
        if ask:
            rows = [r for r in rows if str(r.get("ask_id", "")).upper() == ask]
        if peer:
            rows = [r for r in rows if r.get("peer") == peer]
        try:
            last = int(_opt(rest, "--last", "20"))
        except ValueError:
            last = 20
        rows = rows[-last:] if last > 0 else rows
        if "--json" in rest:
            return "\n".join(json.dumps(r, sort_keys=True) for r in rows) or "[]"
        if not rows:
            return "No receipts yet (%s)." % path
        return "\n".join(format_receipt(r) for r in rows)
    if sub == "verify":
        path = Path(rest[0]) if rest else plugin.receipts().path
        ok, count, problems = core.verify_chain(core.read_receipts(path))
        if ok:
            return "OK: %d receipt(s), hash chain intact (%s)." % (count, path.name)
        return "BROKEN: %d receipt(s), %d problem(s):\n  %s" % (count, len(problems), "\n  ".join(problems[:20]))
    if sub == "compare":
        usage = "Usage: consent compare <other receipts.jsonl> [--mine <path>] [--peer-directory <json>]"
        if not rest:
            return usage
        mine_path = Path(_opt(rest, "--mine")) if _opt(rest, "--mine") else plugin.receipts().path
        mine, theirs = core.read_receipts(mine_path), core.read_receipts(Path(rest[0]))
        peer_directory = None
        if "--peer-directory" in rest:
            directory_path = _opt(rest, "--peer-directory")
            if not directory_path:
                return usage
            try:
                peer_directory = json.loads(Path(directory_path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return "MISMATCH: could not read the trusted peer key directory."
            if not isinstance(peer_directory, dict) or not isinstance(peer_directory.get("keys"), list):
                return "MISMATCH: trusted peer key directory must contain a public keys list."
        lines, chain_issues = [], []
        for label, recs in (("mine", mine), ("theirs", theirs)):
            ok, count, _ = core.verify_chain(recs)
            lines.append("%s: %d receipt(s), chain %s" % (label, count, "intact" if ok else "BROKEN"))
            if not ok:
                chain_issues.append("%s: broken receipt chain (run consent verify on this file)" % label)
        shared, issues, notes = core.compare_report(mine, theirs, peer_directory=peer_directory)
        issues += chain_issues
        notes = ["  note: " + n for n in notes]
        if issues:
            return "\n".join(["MISMATCH: %d issue(s), %d shared ask(s)." % (len(issues), shared)]
                             + ["  " + i for i in issues] + lines + notes)
        return "\n".join(lines + ["Both sides agree on all %d shared ask(s)." % shared] + notes)
    if sub == "declines":
        rows = plugin.declines().active(plugin._expire_days(), plugin._clock())
        if not rows:
            return "No remembered no's."
        return "\n".join(["Remembered no's:"] + ["  %s  %s  %s (%s): %s" % (
            r["id"], core.short_date(r["ts"]), r.get("peer"), r.get("ask_type"), core.one_line(r.get("text", ""), 60))
            for r in rows])
    if sub == "forget":
        if len(rest) != 1:
            return "Usage: consent forget <decline id>"
        rec = plugin.declines().forget(rest[0])
        return ("Forgot %s. The next matching ask will go to you again." % rec["id"]) if rec else \
            "No single remembered no matches '%s'." % rest[0]
    if sub == "policy":
        if len(rest) != 1:
            return "Usage: consent policy <peer>"
        pol = core.load_policy(plugin.peers_dir(), rest[0])
        if pol is None:
            return "No policy for '%s': every ask from that peer is denied." % rest[0]
        return "\n".join([
            "Peer %s (owner %s, file peers/%s)" % (pol.peer, pol.owner, Path(pol.source).name),
            "  allowed:          %s" % (", ".join(sorted(pol.allow)) or "-"),
            "  ask the owner:    %s (and any type not listed)" % (", ".join(sorted(pol.ask_owner)) or "-"),
            "  denied:           %s" % (", ".join(sorted(pol.deny)) or "-"),
            "  always denied:    %s" % ", ".join(sorted(core.HARD_DENY))])
    return USAGE
