# sweetrust-sui

**Let an agent spend from your Sui balance within limits Sui itself enforces, and get a receipt that says which limit stopped it and why.**

It wraps Sui's native allowance (`0x2::allowance`) behind SweeTrust's chain-agnostic delegated-allowance interface ([ADR 0003](../trust/docs/adr/0003-delegated-allowance-interface.md)). There is no Move code of its own: it calls `allowance::new`, `allowance::balance_spend` and `allowance::revoke`, and reads the allowance object back.

```bash
npm i sweetrust-sui @mysten/sui sweetrust
```

`@mysten/sui` (≥ 2.35.0) and `sweetrust` (0.5.x) are peer dependencies. Node ≥ 22, because `@mysten/sui` needs it.

---

## Who holds each limit

Four verbs: `open` (the funder signs), `spend` (the spender signs), `revoke` (the funder signs), and `remaining` (a read). The adapter's one `enforces` declaration says who holds each limit, and every receipt repeats it on a line per limit.

| Limit | Held by | What refuses a spend outside it | On-chain successor |
|---|---|---|---|
| Lifetime cap | **chain** | Sui validators: `allowance::EExceedsLifetimeCap` | (already on chain) |
| Rate (amount per window) | **chain** | Sui validators: `allowance::EExceedsRateLimit` | (already on chain) |
| Start | **chain** | Sui validators: `allowance::ENotStarted` | (already on chain) |
| Expiry | **chain** | Sui validators: `allowance::EExpired` | (already on chain) |
| Recipients | **library** | sweetrust-sui, in-process, before sending | Sui Agent Payments' allowed services (testnet-only, no public package yet), or an app-bound allowance with an audited app module (none public) |
| Per-spend maximum | **nobody** | `open()` refuses the allowance: never silently dropped | Sui Agent Payments' per-payment cap (testnet-only, no public package yet) |

**Chain** means the rule binds every spend the spender's key makes, through any client. **Library** means it binds only spends routed through this library. The full inventory of Sui primitives that could hold each limit, with what was verified and what was not, is in ADR 0003 § *What on Sui could hold each limit*. Walrus (receipt storage), an on-chain anchor for the receipt log, and Seal are noted there and are out of 0.1.

Sui adds two rules of its own, which `open()` checks before sending and explains in words: every allowance needs a lifetime cap or a rate (`ENoLimit`), and an expiry or a rate (`ENoExpiration`).

---

## Worked example: 30 a day, spend 24, then 10 more

This runs on Sui **testnet**. Amounts use a labeled scale, Basecamp's: **1.00 testUSD = 100,000 MIST = 0.0001 testnet SUI**. It is not money; the chain counts MIST, and every receipt carries the base-unit amount beside the label.

You need three testnet keys in a JSON file (`{ "principal": "suiprivkey…", "agent": "…", "merchant": "…" }`). The principal needs SUI in its **address balance** (allowances draw from it, never from coin objects) plus gas; the agent needs gas.

<!-- readme-check: testnet - expect executed refused EExceedsRateLimit true -->
```ts
import { readFileSync } from "node:fs"
import { SuiGrpcClient } from "@mysten/sui/grpc"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { SignedReceiptLog, generateSigningKeypair, makeEd25519ReceiptSigner, verifySignedChain } from "sweetrust/verify"
import { defineScale, suiAllowances } from "sweetrust-sui"

const keys = JSON.parse(readFileSync(process.env.SWEETRUST_SUI_TESTNET_KEYS ?? "keys.json", "utf8"))
const principal = Ed25519Keypair.fromSecretKey(keys.principal) // funds the allowance
const agent = Ed25519Keypair.fromSecretKey(keys.agent)         // spends under it
const merchant = Ed25519Keypair.fromSecretKey(keys.merchant).toSuiAddress()

const testUSD = defineScale({ unit: "testUSD", baseUnitsPerUnit: 100_000n, decimals: 2 })
const receiptSigner = makeEd25519ReceiptSigner(generateSigningKeypair())
const log = new SignedReceiptLog(receiptSigner) // every receipt lands here too, signed

const sui = suiAllowances({
  client: new SuiGrpcClient({ network: "testnet", baseUrl: "https://fullnode.testnet.sui.io:443" }),
  network: "sui:testnet",
  scale: testUSD,
  log,
})

// The principal signs: the agent may spend 30.00 testUSD a day, to the merchant only.
const opened = await sui.open({
  signer: principal,
  allowance: {
    network: "sui:testnet",
    asset: "0x2::sui::SUI",
    spender: agent.toSuiAddress(),
    limits: { rate: { amount: testUSD.of(30), windowMs: 86_400_000 }, recipients: [merchant] },
  },
  name: "README: 30 a day",
})
if (opened.allowance === null) throw new Error(opened.receipt.summary)

// The agent signs. Sui holds the rate; the library holds the recipient list.
const first = await sui.spend({ signer: agent, allowance: opened.allowance, amount: testUSD.of(24), recipient: merchant })
const second = await sui.spend({ signer: agent, allowance: opened.allowance, amount: testUSD.of(10), recipient: merchant })

// The principal revokes: the allowance object is deleted on chain.
await sui.revoke({ signer: principal, allowance: opened.allowance })

const verified = verifySignedChain(log.signed(), { trustedSignerPublicKeyHex: receiptSigner.publicKeyHex }).valid
console.log(first.verdict, second.verdict, second.refusal?.native?.abortName, verified)
console.log(JSON.stringify(second, null, 2))
```

It prints `executed refused EExceedsRateLimit true`, then the second spend's receipt. This one is from a real run:

```json
{
  "schema": "sweetrust-sui/receipt@1",
  "verb": "spend",
  "verdict": "refused",
  "network": "sui:testnet",
  "asset": "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
  "allowanceId": "0x6b5cea8192078601f74089ea412591594b7fa0fdf2eb08cca3d6977bdcf7ce1c",
  "digest": "HBwhgKqGYfuztwrVkMQhhTW4LBjKKE16KpXjoKHZbgXU",
  "explorer": "https://suiscan.xyz/testnet/tx/HBwhgKqGYfuztwrVkMQhhTW4LBjKKE16KpXjoKHZbgXU",
  "at": "2026-11-07T01:33:26.623Z",
  "atSource": "chain",
  "funder": "0xede24c3027041f85527166aa099bf11976c672e4f7cf822c4645a3cd850d62be",
  "spender": "0x16809e9fff92aaf21b865f759c38bebacc6d09e6974915876cb22be5c3925a46",
  "amount": "1000000",
  "amountText": "10.00 testUSD",
  "recipient": "0x16b7c5a22d9ae356215e3d8ee62a946199e1c78bc25a1ae49ef851db233be713",
  "limits": [
    {
      "limit": "rate",
      "value": "30.00 testUSD per day, in fixed windows counted from the first charge",
      "heldBy": "chain",
      "verdict": "outside",
      "why": "Refused by Sui validators (allowance::EExceedsRateLimit): this 10.00 testUSD spend would bring the current window to 34.00 testUSD, over the rate of 30.00 testUSD per day. Sui's window is fixed: it opened at the first charge (2026-11-07 01:33:25 UTC) and resets at 2026-11-08 01:33:25 UTC."
    },
    {
      "limit": "recipients",
      "value": "1 address: 0x16b7c5…3be713",
      "heldBy": "library",
      "verdict": "within",
      "why": "Held by the library, in-process: the payee 0x16b7c5…3be713 was checked against the allowed list before sending. On Sui this limit can move on-chain through Sui Agent Payments' allowed services, which is testnet-only with no public package yet, or through an app-bound allowance (allowance::propose_for_app), which needs an audited app module; none is public."
    }
  ],
  "refusal": {
    "code": "rate-exceeded",
    "refusedBy": "chain",
    "native": {
      "module": "0x2::allowance",
      "abortName": "EExceedsRateLimit",
      "abortCode": 4,
      "rawAbortCode": "13836185853565075465"
    },
    "why": "Refused by Sui validators (allowance::EExceedsRateLimit): this 10.00 testUSD spend would bring the current window to 34.00 testUSD, over the rate of 30.00 testUSD per day. Sui's window is fixed: it opened at the first charge (2026-11-07 01:33:25 UTC) and resets at 2026-11-08 01:33:25 UTC."
  },
  "summary": "Refused by Sui validators (allowance::EExceedsRateLimit): this 10.00 testUSD spend would bring the current window to 34.00 testUSD, over the rate of 30.00 testUSD per day. Sui's window is fixed: it opened at the first charge (2026-11-07 01:33:25 UTC) and resets at 2026-11-08 01:33:25 UTC."
}
```

The spend was refused by Sui's validators, not by this library: the transaction executed, aborted inside `0x2::allowance`, and its digest is on chain. A refused spend costs the spender gas; that is the price of a refusal anyone can look up.

---

## Refused before anything is sent

A limit nobody can hold, or an allowance that breaks Sui's own rules, is refused at `open()` with a receipt and no transaction. This block runs offline:

<!-- readme-check: run - expect refused limit-unheld nobody refused unbounded-time ENoExpiration -->
```ts
import { SuiGrpcClient } from "@mysten/sui/grpc"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { SUI, suiAllowances } from "sweetrust-sui"

const sui = suiAllowances({
  client: new SuiGrpcClient({ network: "testnet", baseUrl: "https://fullnode.testnet.sui.io:443" }),
  network: "sui:testnet",
})
const grant = (limits: Parameters<typeof sui.open>[0]["allowance"]["limits"]) => sui.open({
  signer: Ed25519Keypair.generate(),
  allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: Ed25519Keypair.generate().toSuiAddress(), limits },
})

// A per-spend maximum: nobody holds it on Sui in 0.1, so the allowance is refused, not opened without it.
const perSpend = (await grant({ rate: { amount: SUI.of("0.03"), windowMs: 86_400_000 }, perSpendMax: SUI.of("0.01") })).receipt
console.log(perSpend.verdict, perSpend.refusal?.code, perSpend.limits.find((l) => l.limit === "perSpendMax")?.heldBy)

// A lifetime cap alone never ends, and Sui requires an expiry or a rate.
const forever = (await grant({ lifetimeCap: SUI.of("0.05") })).receipt
console.log(forever.verdict, forever.refusal?.code, forever.refusal?.native?.abortName)
```

The second receipt's `why`: *"Refused at open(); nothing was sent to Sui. Sui's rule (0x2::allowance::ENoExpiration, abort code 15): every allowance has an expiry or a rate, so it can never be unbounded in time. A lifetime cap alone never ends; add an expiry, or a rate."*

---

## How a stranger checks it

1. **The chain.** Open the receipt's `explorer` link, or fetch `digest` from any Sui fullnode for its `network`. A refusal is a failed transaction whose effects quote the abort the receipt names (`native.abortName`, `native.rawAbortCode`). The four refusals this package's conformance suite recorded are in [`test/conformance/testnet-digests.json`](test/conformance/testnet-digests.json), one per limit Sui holds. (Testnet fullnodes prune old transactions; an archival source such as Sui GraphQL keeps them longer.)
2. **The signed log, if you used one.** Publish `log.exportJSONL()` and the receipt signer's public key; anyone re-checks every signature and hash link holding only public material:

<!-- readme-check: prelude
declare const jsonl: string
declare const publishedKey: string
-->
```ts
import { parseJSONL, verifySignedChain } from "sweetrust/verify"

const report = verifySignedChain(parseJSONL(jsonl), { trustedSignerPublicKeyHex: publishedKey })
// report.valid; each record's payload.args.receipt.value is a sweetrust-sui receipt, digest included
```

The receipt enters that log at tier `untrusted`: it is this library's account of what happened, and the digest beside it is what a stranger actually checks.

---

## Honest limits

- **A hijacked host can spend whatever the chain allows.** The spender's key lives on the host. Anyone holding it can spend up to the chain-held limits (lifetime cap, rate, start, expiry), through any client, to anyone. Only `revoke` stops that, and only the funder can sign it.
- **Library-held limits bind only spends routed through this library.** The recipient list is checked in-process before sending. The same key, used from another client, can pay any address. The list lives in the handle `open()` returns, not on chain: persist that handle if the host restarts.
- **Sui's rate window is fixed, not rolling.** The first charge opens the first window; each later window starts exactly one period after the last. So up to **twice** the rate can pass across a boundary: a full window's worth just before it, and another just after.
- **No per-spend maximum in 0.1.** `open()` refuses one rather than drop it. Bound the total with the rate and the lifetime cap until a Sui primitive with a public package can hold it.
- **`remaining()` reads the chain-held limits, not the funder's balance.** An allowance can permit more than the funder's address balance holds; the spend then fails for lack of funds.
- **Testnet only, so far.** The conformance suite has run on testnet. The module is present on mainnet (read 2026-11-06), and this package has not spent there.

---

## Proof it runs

```bash
pnpm -C packages/sui test        # receipts and WHY text against a mocked fullnode; the recorded refusals' fixture
SWEETRUST_SUI_TESTNET_KEYS=/path/keys.json pnpm -C packages/sui test:testnet   # four real refusals on testnet
pnpm -C packages/sui typecheck   # tsc, then this README's blocks against dist/ (the testnet block runs only with keys)
```

Without keys the testnet suite is skipped, and it says so in a banner on every run.

## Status

**0.1.0, unreleased.** Not on npm. Plain allowances only: the app-bound path (`allowance::propose_for_app`) is the slot a Sui agent product with a public package fills later. `CHANGELOG.md` ships in the tarball.

## License

Apache-2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
