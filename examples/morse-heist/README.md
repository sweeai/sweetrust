# The Morse code heist

An attacker gets one AI agent to pay out, using nothing but another AI agent's public post.

The attacker gives a translator bot a membership token, which unlocks a banker bot's transfer tool. Then the attacker writes a transfer order in Morse code and asks the translator what it says. The translator posts the plain text and tags the banker. The banker reads any post that tags it as its owner's command, so it pays.

This example retells that attack three times on mocks: once with no guard, once with a SweeTrust spending limit, and once with SweeTrust provenance. It retells a real incident on Base. The bots, the timeline and the ledger here are stand-ins, and SweeTrust was not involved in the real event.

## Run it

From an empty folder, on Node 20.19 or later:

```bash
npm i sweetrust@0.7.0 && curl -fsSLO https://raw.githubusercontent.com/sweeai/sweetrust/main/examples/morse-heist/heist.mjs && node heist.mjs
```

From a clone of this repository: `cd examples/morse-heist && npm install && npm start`.

It runs offline: no network after the install, no keys and no chain.

## What you will see

```text
run 1 · no guard
  the banker treats the post as its owner's command · the attacker now holds 3,000,000,000 COIN
  → PAID OUT

run 2 · spending limit (a SweeTrust mandate whose limit is 0 until the owner raises it)
  the banker asks the kernel before moving anything → MandateLimitExceeded · the attacker holds 0 COIN
  → BLOCKED by the spending limit

run 3 · provenance (no limit; the payee and amount must come from the owner)
  the banker labels the post's values as written by another AI, in public
  the post's order is refused: its payee and amount are untrusted (origin llm:public-post:@translator)
  the owner's own 100 COIN order still ran · the attacker holds 0 COIN
  → BLOCKED by provenance: a public post is not the owner's signature
```

## What each run shows

**Run 1, no guard.** The banker cannot tell its owner's order from a stranger's post. Every word of the order came from the attacker, but by the time it reached the banker it was an ordinary string from a member it trusted.

**Run 2, a spending limit** (`sweetrust/mandate`). The banker's transfers sit behind a mandate whose limit is 0 until the owner raises it. The banker asks the kernel before moving anything, and the kernel refuses. A limit bounds the damage no matter who wrote the order. It also bounds the owner, who has to raise it to spend.

**Run 3, provenance** (`sweetrust/gate`). There is no limit at all. The transfer is a sink that runs only when its payee and amount are `verified`, meaning they came from the owner. A value parsed out of another AI's public post is labeled as model output, so it is untrusted however convincing it reads, and the sink refuses it. The owner's own order, through the owner's own channel, still runs through the same sink.

## The honest limit

Provenance is only as good as the label the host puts on a value. Run `HOST_TRUSTS_POSTS=1 node heist.mjs` to watch a host label the post as the owner's word: run 3 then pays out, and says so. SweeTrust checks where a value came from; it cannot know where a value came from if the host tells it wrong.

The script exits 1 if any run ends differently from what is described here.
