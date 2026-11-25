"""Shared consent behavior with a fictional catalog and local state only.

Run: python3 -m unittest tests.test_shared_case
"""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests._load import load

plugin, core, _ = load()


class TestSharedCase(unittest.TestCase):
    def test_read_only_approval_decline_and_expiry(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        state = Path(work.name)
        (state / "peers").mkdir()
        (state / "peers" / "catalog-reader.yaml").write_text(
            "peer: catalog-reader\nowner: librarian\nallow: [status_question]\nask_owner: [catalog_read]\n",
            encoding="utf-8")
        config = {"state_dir": str(state), "pending_ttl_hours": 1}
        now = 1_800_000_000.0
        notices = []

        def notify(target, message):
            notices.append(message)
            return True

        door = plugin.ConsentNetwork(config.get, profile="public-library", notifier=notify, clock=lambda: now)
        source = SimpleNamespace(platform="a2a", user_id="catalog-reader")
        rows = []

        def ask(ask_id, body):
            return core.ask_header("catalog_read", ask_id) + "\n" + body

        def code(ask_id):
            return door.pending().get(f"{source.user_id}/{ask_id}")["code"]

        def send(label, message, decision, reason, *, show_body=False):
            prompt = door.pre_gateway_dispatch(event=SimpleNamespace(source=source, text=message))["text"]
            receipt = door.receipts().read()[-1]
            body = message.split("\n", 1)[1]
            observed = receipt["decision"], receipt["reason"]
            self.assertEqual(observed, (decision, reason))
            self.assertEqual(body in prompt, show_body)
            if label:
                rows.append((label, *observed))

        first = ask("DEMO0001", "May I summarize the public catalog entry for the oak exhibit?")
        send(None, first, "ask_owner", "listed_for_owner")
        self.assertTrue(door.answer(code("DEMO0001"), True).startswith("Approved"))
        send("Owner-approved read-only ask", first, "allow", "owner_approved", show_body=True)
        send("Identical owner-approved resend", first, "deny", "approval_already_used")
        send("Same ID, different text", ask("DEMO0001", "May I read the public maple exhibit entry?"),
             "deny", "ask_id_reused_with_different_text")
        self.assertEqual(len(notices), 1)

        original = ask("DEMO0002", "May I list the public photos in the spring catalog?")
        send(None, original, "ask_owner", "listed_for_owner")
        self.assertTrue(door.answer(code("DEMO0002"), False).startswith("Declined"))
        send("Owner-declined ask", original, "deny", "owner_declined")
        send("Reworded ask after a denial", ask("DEMO0003", "Please list the public photos in the spring catalog."),
             "deny", "remembered_no")
        self.assertEqual(len(notices), 2)

        expiring = ask("DEMO0004", "Can I read tomorrow's opening hours?")
        send(None, expiring, "ask_owner", "listed_for_owner")
        now += 3600
        self.assertIn("expired", door.answer(code("DEMO0004"), True))
        send("Unanswered ask resent after expiry", expiring, "ask_owner", "listed_for_owner")
        self.assertEqual(len(notices), 4)

        allowlisted = core.ask_header("status_question", "DEMO0005") + "\nIs the public catalog online?"
        send(None, allowlisted, "allow", "allow_list", show_body=True)
        send("Identical allow-listed resend", allowlisted, "duplicate", "previously_allowed")
        self.assertEqual(len(notices), 4)

        print("\n| Case | Decision | Reason |\n|---|---|---|")
        for label, decision, reason in rows:
            print(f"| {label} | `{decision}` | `{reason}` |")


if __name__ == "__main__":
    unittest.main()
