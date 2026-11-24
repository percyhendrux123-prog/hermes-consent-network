# hermes-consent-network

Hermes can already talk to other agents over A2A. What it can't yet do is let **someone else's** agent ask yours for things under rules you set. Today the rule is all or nothing: a peer is trusted or it isn't, and a trusted peer's text goes straight to your model.

This plugin adds the missing layer. Each peer gets a small YAML allow-list. Asks inside it go through. Asks outside it become **one question to you**, through the `hermes send` path you already use. A no is remembered. Money, prices, sends to third parties and deletions are always refused. Every ask on both sides writes a hash-chained receipt you can read with `hermes consent receipts`.

It's a plugin. It doesn't change Hermes core.

Discussion and open design questions: [NousResearch/hermes-agent#159584](https://github.com/NousResearch/hermes-agent/issues/159584).

## How an ask moves

```
bob-agent                                   alice-agent                         Alice
---------                                   -----------                         -----
a2a_call  "consent-ask: calendar_hold id=H4T8K2D6
           Please hold Thursday 2 PM..."
  pre_tool_call: has a type + id? not a
  hard-denied type? -> receipt (out, sent)
                    ---- A2A ---->  pre_gateway_dispatch (platform a2a)
                                    peer = A2A credential identity, not the body
                                    policy peers/bob-agent.yaml says: ask the owner
                                    -> pending, receipt (in, ask_owner)
                                    -> hermes send -t telegram ------------>  "bob-agent's agent asks
                                    model sees only: WAITING, text withheld      (calendar_hold): ...
                    <--- [INPUT_REQUIRED] consent: H4T8K2D6 waiting             consent yes MUWKAN?"
  post_tool_call -> receipt (out, waiting)                                  "consent yes MUWKAN"
                                    pre_gateway_dispatch (telegram, owner id) <--
                                    -> approved, receipt (owner_answer)
a2a_call (same id, same text) ---->  approved and unused -> model sees the ask
                    <--- consent: H4T8K2D6 allowed / Done...
  post_tool_call -> receipt (out, allowed)
```

## The rules, in order

For every inbound A2A ask, the plugin decides before the model sees anything:

1. **No policy file for this peer** -> denied. Nobody is asked.
2. **Always-denied type** (`money`, `payment`, `refund`, `price`, `pricing`, `send_third_party`, `delete_data`) -> denied. No allow-list can open these.
3. **The owner already answered this exact ask.** The answer is bound to the peer, the ask id and the text hash. A yes works once. A no stays a no. Re-using an id with different words is denied.
4. **On the peer's deny list** -> denied.
5. **On the peer's allow list** -> allowed.
6. **Anything else** (listed under `ask_owner`, not listed at all, or no `consent-ask` line): first check the remembered no's. A near match (same peer, same type, similar wording) is denied without asking. Otherwise it becomes one question to the owner. A peer can have at most `max_pending` (default 3) questions open at once.

When an ask is denied or waiting, the model gets a short notice and **not the request text**. It can't act on what it never saw. When the plugin itself errors on an A2A ask, it denies. Everywhere else it fails open, like its sibling plugins.

Outbound, the plugin blocks `a2a_call` / `a2a_orchestrate` / `message_agent` messages that have no `consent-ask: <type> id=<id>` first line, and it never sends always-denied types. Your agent learns the format from the block message.

## A peer policy

`<state_dir>/peers/bob-agent.yaml` (file name = the peer's A2A identity):

```yaml
peer: bob-agent          # must match the file name
owner: alice             # who gets asked, and whose name goes on approvals
notify_to: telegram      # hermes send target; falls back to owner_notify_to
allow: [status_question, site_edit]
ask_owner: [calendar_hold]
deny: [contact_export]
max_pending: 3
```

## Answering

Any of these work:

- In chat, from an id listed in `owner_ids`: `consent yes MUWKAN` or `consent no MUWKAN`. The message is consumed by the plugin and never reaches the agent.
- In a session: `/consent approve MUWKAN`, `/consent deny MUWKAN`, `/consent pending`.
- In a shell: `hermes consent approve MUWKAN`.

The peer gets the answer the next time it sends the same ask. The waiting reply tells its agent to do that.

## Receipts

`<state_dir>/receipts.jsonl`, 0600 in a 0700 directory, append-only. One line per event: `ask`, `owner_answer`, `result`.

```json
{"v":1,"seq":6,"ts":"2026-11-24T18:01:45Z","side":"alice-agent","direction":"in","event":"ask",
 "ask_id":"H4T8K2D6","peer":"bob-agent","owner":"alice","ask_type":"calendar_hold",
 "summary":"Please hold Thursday 2 PM for my team's tasting, 6 people.","text_sha256":"...",
 "decision":"allow","reason":"owner_approved","decided_by":"owner:alice",
 "prev":"<hash of seq 5>","hash":"<sha256 of this line without hash>"}
```

- `hermes consent receipts [--ask ID] [--peer NAME] [--last N] [--json]`
- `hermes consent verify [path]` checks every line's hash, the link to the line before and the sequence. An edit, a deletion, a reorder or an insertion breaks it.
- `hermes consent compare <other side's receipts.jsonl>` matches the two sides by ask id. It checks they hashed the same text, recorded the same type and reached the same decision.

Receipts store a 120-character summary of the ask (turn off with `store_summary: false` to keep only the hash), never the agent's reply (hash and length only), and no credentials.

**What a receipt does not prove.** A chain shows the file hasn't been edited since it was written. It can't show the tail wasn't cut off, and anyone with write access to the directory can rebuild a whole new chain. Comparing with the other side's file is what catches both. A receipt also doesn't prove the allowed work was done well, only who asked, what was decided and by whom.

## Settings

Under `plugins.entries.hermes-consent-network.settings`:

| key | default | meaning |
|---|---|---|
| `state_dir` | `<HERMES_HOME>/plugins-state/hermes-consent-network` | receipts, pending asks, remembered no's |
| `peers_dir` | `<state_dir>/peers` | one `<peer>.yaml` per peer |
| `owner_notify_to` | none | `hermes send` target when a policy has no `notify_to` |
| `owner_ids` | none | `platform:user_id` entries allowed to answer from chat |
| `pending_ttl_hours` | 24 | an unanswered ask is asked again after this |
| `remember_no_days` | 30 | how long a no holds; 0 turns it off |
| `similarity` | 0.6 | how close new wording must be to a declined ask to count as the same |
| `require_outbound_header` | true | block outbound asks with no `consent-ask` line |
| `store_summary` | true | keep the 120-character summary on receipts |

## Demo: alice-agent and bob-agent

`python3 demo/run_demo.py demo/receipts` runs two fictional local agents through the real plugin code. Only the A2A wire, the model and Telegram are stand-ins (in-process). The full output is in [`demo/TRANSCRIPT.txt`](demo/TRANSCRIPT.txt) and both sides' receipt files are in `demo/receipts/`.

| # | bob-agent asks | alice-agent's rule | what happens |
|---|---|---|---|
| 1 | `status_question`: is the spring menu live? | allow list | Alice's model answers. Nobody is pinged. |
| 2 | `calendar_hold`: hold Thursday 2 PM | ask the owner | Alice gets one Telegram question. Her model sees only "waiting". She replies `consent yes MUWKAN`. Bob re-sends and gets the hold. |
| 3 | `contact_export`: send your customer list | deny list | Denied. Alice's model never sees the request. Alice isn't asked. |
| 3b | `pricing`: drop the catering price | always denied | Bob's **own** plugin refuses to send it. |
| 4 | `newsletter_feature`, twice, worded differently | not listed | The first one goes to Alice and she says no. A week later the reworded ask is denied from memory, with no second question. |

At the end, both chains verify (14 and 13 receipts). `compare` finds all 5 shared asks agree. It notes that bob-agent hasn't yet collected Alice's no on ask 4. Flipping one `deny` to `allow` in a copy of Alice's file makes `verify` report `BROKEN ... line 8`.

## In production, in prose

The pattern already runs between two real Hermes installs: an operator's agent and a client's agent, over Hermes's A2A channel. The client's agent takes an ask only with the client's direct yes. Today that rule lives in the client agent's instructions. This plugin moves it into code with receipts. No real thread, message or file from that setup is in this repo.

## Known limits

- Covers A2A asks that reach the gateway's normal inbound path (`pre_gateway_dispatch`). A2A agents served for another profile through `forward_to_owner` skip that hook today. That path is not covered (checked against source; not run live).
- Approval comes back on the peer's next send of the same ask. There is no push to the waiting peer yet.
- Ask types are declared by the asking agent. The plugin trusts the peer's identity (from A2A credentials), not its labels. That's why unknown and unlabeled asks go to the owner and labels can't open hard-denied types. A peer that mislabels a pricing ask as `status_question` gets an allowed status question. The model is told to do only what that type needs, and the receipt records the label it used.
- Not installed in any live profile. `hermes plugins validate` passes. The `hermes consent` CLI registration was checked by validate and unit test, not run from an installed copy.

## Tests

```sh
python3 -W error::ResourceWarning -m unittest discover -s . -p 'test_*.py' -t .
hermes plugins validate .
```

Stdlib only. PyYAML is used if present, otherwise a small built-in parser for the policy shape above. macOS and Linux (`fcntl`).

## Related

Part of a set of small consent and evidence plugins: [run-receipts](https://github.com/NousResearch/hermes-agent/pull/158864) (what a scheduled run actually did), [hermes-declines](https://github.com/NousResearch/hermes-agent/pull/158865) (a no to a scheduled job sticks; this plugin reuses that pattern for peer asks), [repeat-pause](https://github.com/NousResearch/hermes-agent/pull/158886), and the proactivity roadmap issue [#158538](https://github.com/NousResearch/hermes-agent/issues/158538).

MIT.


## Agent identity (Web Bot Auth)

A2A tokens say "the owner gave this peer a key". They don't help when an agent you have never met
shows up. `identity.py` adds the other half, on an IETF standard instead of a new format:
**Web Bot Auth** (draft-ietf-webbotauth-httpsig-protocol), which is HTTP Message Signatures
(RFC 9421) with the agent's public keys published at
`https://<owner-domain>/.well-known/http-message-signatures-directory`.

- The transport that terminates HTTP checks the signature (`identity.Verifier`) and attaches the
  result to the inbound event as `agent_identity`. Text in a message can never set it.
- A verified domain becomes the peer name: `peers/<domain>.yaml` applies (a **partner**: the owner
  listed it). An unlisted verified domain gets `verified_default_policy` if you set one
  (**domain_verified**). No signature and no A2A token: refused, as before.
- Policies can demand a level per ask type: `require_partner: [calendar_hold]`,
  `require_domain_verified: [...]`.
- A signature that fails (forged key, wrong domain, replayed, expired, tampered) is refused outright,
  and receipts record `identity`, `verified_domain`, `keyid` and the hash of the caller's signature.

It proves which domain's owner stands behind an agent. It does not prove that owner is honest.
Needs `cryptography`; without it the plugin behaves exactly as 0.1.0. Open question for Hermes core:
the A2A server would need to run the check and set `agent_identity` on the event.
The verifier also checks the directory response's own signatures (tag `http-message-signatures-directory`,
over `"@authority";req`), as the draft requires of a verifier relying on the domain, so a copied key file on
another host earns nothing.
Tests: `tests/test_identity.py` (fictional domains, no network). With `cryptography` installed all 62 tests run:
`uv run --with cryptography --with pyyaml python -m unittest discover -s . -p 'test_*.py' -t .`

Working reference: the same `identity.py` runs in [agent-front-door](https://github.com/percyhendrux123-prog/agent-front-door),
whose hosted door checks signatures live at https://axiom-front-door.percyhendrux123.workers.dev/mcp. Deploy Axiom's
agents sign with the key published at https://deployaxiom.com/.well-known/http-message-signatures-directory.
