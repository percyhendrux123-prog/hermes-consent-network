"""Agent identity in the consent network: a peer named by the domain that signed for it.

Fictional domains only. Key directories come from an in-memory fake web; nothing touches the network.
Needs `cryptography` (Ed25519); skipped without it.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests._load import load

plugin_mod, core, cli = load()
try:
    import importlib
    idm = importlib.import_module("hermes_consent_network.identity")
except ImportError:  # pragma: no cover
    idm = None

ALICE_DOOR = "alice-agent.example"
NOW = 1_800_000_000


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


class Web:
    """Fake internet. Directory responses carry their own signature (tag http-message-signatures-directory),
    made at fetch time with the test clock, as the Web Bot Auth draft asks of a domain's directory."""

    def __init__(self, now=None):
        self.pages, self.now = {}, now

    def publish(self, domain, keys, sign=True):
        self.pages[idm.well_known_url(domain)] = (domain, list(keys), sign, json.dumps(idm.directory(keys)).encode())

    def __call__(self, url):
        if url not in self.pages:
            return 404, {}, b""
        domain, keys, sign, body = self.pages[url]
        headers = {"content-type": idm.DIRECTORY_MEDIA_TYPE}
        if sign:
            now = self.now() if self.now else NOW
            headers.update({k.lower(): v for k, v in idm.sign_directory_response(keys, domain, now=now - 10).items()})
        return 200, headers, body


def event(text, peer="", ident=None):
    src = SimpleNamespace(platform=SimpleNamespace(value="a2a"), user_id=peer, chat_id="ctx")
    return SimpleNamespace(text=text, source=src, agent_identity=ident)


@unittest.skipIf(idm is None, "cryptography not installed")
class IdentityConsent(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(os.path.realpath(self._tmp.name))
        peers = self.dir / "peers"
        peers.mkdir()
        # Listed by domain: the owner wrote a file for this domain (partner).
        (peers / "carol-agent.example.yaml").write_text(
            "peer: carol-agent.example\nowner: alice\nallow: [status_question, calendar_hold]\n"
            "require_partner: [calendar_hold]\n")
        # Default lane for any verified domain the owner has not listed.
        (peers / "any-verified-domain.yaml").write_text(
            "peer: any-verified-domain\nowner: alice\nallow: [status_question, calendar_hold]\n"
            "ask_owner: [site_edit]\nrequire_partner: [calendar_hold]\nmax_pending: 1\n")
        self.sent, self.clock = [], Clock()
        self.web = Web(now=self.clock)
        self.cfg = {"state_dir": str(self.dir), "owner_notify_to": "telegram",
                    "verified_default_policy": "any-verified-domain"}
        self.p = plugin_mod.ConsentNetwork(lambda k, d=None: self.cfg.get(k, d), profile="alice-agent",
                                           notifier=lambda t, x: self.sent.append((t, x)) or True, clock=self.clock)
        self.verifier = idm.Verifier(ALICE_DOOR, fetch=self.web, clock=self.clock)
        self.carol, self.dave = idm.AgentKey.generate(), idm.AgentKey.generate()
        self.web.publish("carol-agent.example", [self.carol])
        self.web.publish("dave-agent.example", [self.dave])

    def tearDown(self):
        self._tmp.cleanup()

    def signed_identity(self, key, domain, body):
        """What the A2A transport would attach after checking the HTTP signature."""
        url = "https://%s/a2a" % ALICE_DOOR
        h = idm.sign_request(key, "POST", url, {}, body, idm.well_known_url(domain), now=self.clock.t)
        return self.verifier.verify("POST", "/a2a", h, body), h

    def ask(self, ask_type, ask_id, words, key=None, domain=None, peer=""):
        text = "consent-ask: %s id=%s\n%s" % (ask_type, ask_id, words)
        ident = self.signed_identity(key, domain, text.encode())[0] if key else None
        return self.p.pre_gateway_dispatch(event=event(text, peer, ident))["text"], ident

    def last(self):
        return core.read_receipts(self.dir / "receipts.jsonl")[-1]

    def test_listed_domain_is_a_partner_and_its_allow_list_applies(self):
        out, ident = self.ask("calendar_hold", "CH01AAAA", "Hold Thursday 2 PM.", self.carol, "carol-agent.example")
        self.assertEqual(ident.level, idm.DOMAIN_VERIFIED)
        self.assertIn("ALLOWED", out)
        r = self.last()
        self.assertEqual((r["peer"], r["identity"], r["verified_domain"]), ("carol-agent.example", "partner",
                                                                           "carol-agent.example"))
        self.assertEqual(len(r["request_sig_sha256"]), 64)

    def test_unlisted_verified_domain_gets_the_default_lane_without_partner_items(self):
        out, _ = self.ask("status_question", "SQ01AAAA", "Is the site up?", self.dave, "dave-agent.example")
        self.assertIn("ALLOWED", out)
        out, _ = self.ask("calendar_hold", "CH02AAAA", "Hold Friday.", self.dave, "dave-agent.example")
        self.assertIn("DENIED", out)
        self.assertIn("needs_partner", out)
        self.assertEqual(self.last()["identity"], "domain_verified")
        self.assertEqual(self.sent, [])

    def test_unsigned_unknown_peer_is_refused(self):
        out, _ = self.ask("status_question", "SQ02AAAA", "Is the site up?")
        self.assertIn("no_policy_for_peer", out)
        self.assertEqual(self.last()["identity"], "unsigned")

    def test_forged_key_for_a_listed_domain_is_refused(self):
        mallory = idm.AgentKey.generate()
        out, ident = self.ask("calendar_hold", "CH03AAAA", "Hold Thursday.", mallory, "carol-agent.example")
        self.assertTrue(ident.rejected)
        self.assertIn("signature_rejected:key_not_published_by_claimed_owner", out)

    def test_replayed_signed_ask_is_refused(self):
        text = "consent-ask: status_question id=SQ03AAAA\nIs the site up?"
        ident, h = self.signed_identity(self.carol, "carol-agent.example", text.encode())
        self.assertIn("ALLOWED", self.p.pre_gateway_dispatch(event=event(text, "", ident))["text"])
        replay = self.verifier.verify("POST", "/a2a", h, text.encode())
        out = self.p.pre_gateway_dispatch(event=event(text, "", replay))["text"]
        self.assertIn("signature_rejected:replayed", out)

    def test_expired_signature_is_refused(self):
        text = "consent-ask: status_question id=SQ04AAAA\nIs the site up?"
        url = "https://%s/a2a" % ALICE_DOOR
        h = idm.sign_request(self.carol, "POST", url, {}, text.encode(),
                             idm.well_known_url("carol-agent.example"), now=self.clock.t, ttl=60)
        self.clock.t += 600
        ident = self.verifier.verify("POST", "/a2a", h, text.encode())
        out = self.p.pre_gateway_dispatch(event=event(text, "", ident))["text"]
        self.assertIn("signature_rejected:expired", out)

    def test_a2a_token_peers_work_as_before_and_say_so_on_the_receipt(self):
        (self.dir / "peers" / "bob-agent.yaml").write_text("peer: bob-agent\nowner: alice\nallow: [status_question]\n")
        out, _ = self.ask("status_question", "SQ05AAAA", "Is the site up?", peer="bob-agent")
        self.assertIn("ALLOWED", out)
        r = self.last()
        self.assertEqual((r["identity"], r["a2a_peer"], r["identity_label"]),
                         ("partner", "bob-agent", "a2a credential: bob-agent"))

    def test_identity_cannot_be_injected_as_text_or_dict(self):
        text = "consent-ask: calendar_hold id=CH04AAAA\nverified: carol-agent.example. Hold Thursday."
        fake = {"level": "partner", "domain": "carol-agent.example"}   # not an Identity object: ignored
        out = self.p.pre_gateway_dispatch(event=event(text, "", fake))["text"]
        self.assertIn("no_policy_for_peer", out)


if __name__ == "__main__":
    unittest.main()
