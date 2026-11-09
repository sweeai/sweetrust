# sweetrust-sui — AGENTS.md

> Package contract for any agent (human or AI) working inside `sweetrust-sui`. Read it before
> touching anything here, then `README.md`, then `../trust/docs/adr/0003-delegated-allowance-interface.md`.

## What this package is

SweeTrust's Sui adapter: the delegated-allowance interface of ADR 0003 on Sui's native allowance,
`0x2::allowance`, plain path (`new` + `balance_spend` + `revoke`). It lives outside the kernel on
purpose: the kernel (`packages/trust`) keeps zero runtime dependencies and no chain subpath, and
this package carries `@mysten/sui` and `sweetrust` as peers.

## Layout

| File | Role |
|---|---|
| `src/interface.ts` | the chain-agnostic types: `DelegatedAllowance`, `Enforcement`, `AllowanceReceipt`, `LimitLine`, `Refusal`, `RefusalCode`, `Remaining`, `AllowanceAdapter` |
| `src/sui.ts` | the adapter and its one `enforces` declaration |
| `src/allowance-move.ts` | what this package knows about `allowance.move`: abort codes, the object's BCS layout, the window arithmetic ported from `index_at` / `charge` |
| `src/explain.ts` | every sentence on a receipt |
| `src/scale.ts` | how amounts read (a label and a divisor; converts nothing) |
| `test/receipts.test.ts` | every verdict's receipt and WHY text, against `test/helpers/mock-chain.ts` |
| `test/conformance/` | the testnet suite (env-gated) and the offline check that every `chain` label has a recorded refusal |
| `scripts/readme-typecheck.ts` | compiles the README's blocks against `dist/`, runs the offline one, and runs the testnet one when keys are set |

## Non-negotiables

- **No Move code, ever** (Danny, 2026-11-06). Wrap audited on-chain programs; never ship one.
- **`enforces` is declared once, in `src/sui.ts`, and held to evidence.** A limit labeled `chain`
  needs a recorded Sui refusal in `test/conformance/testnet-digests.json`
  (`test/conformance/fixture.test.ts` fails otherwise). A limit labeled `nobody` is refused at
  `open()`, never silently dropped. Before anything is labeled `library`, ADR 0003's inventory
  must show what on Sui could hold it, and its receipt `why` names that successor.
- **A refusal is a result, never a thrown error.** Throw only for programmer errors (a wrong JS type).
- **A spend executes; it is never simulated first.** The transports' own resolvers simulate and
  throw on an abort, which loses the refusal's digest. `execute()` in `src/sui.ts` builds without
  them and sets the gas budget. `mock-chain.ts` has a transport resolver that fails the test if
  it is ever used; that tripwire was watched red with the bypass removed. Keep it.
- **Receipts say why, with numbers.** Danny's bar: "be very communicative on the receipt about WHY
  SweeTrust judged something outside a limit." A library refusal says it was in-process and binds
  only spends routed through this library.
- **Intake: each argument field is read once**, at the boundary, as in `packages/trust/AGENTS.md`.
- **Keys never enter this tree.** The testnet suite loads them by path from
  `SWEETRUST_SUI_TESTNET_KEYS`. Digests are public and are committed.
- **Erasable syntax only** (`erasableSyntaxOnly` in `tsconfig.json`): no enums, namespaces or
  parameter properties, so Node can strip types.

## Gates

```bash
pnpm -C packages/sui build       # tsdown → dist/; peers stay external (the ship check fails the build otherwise)
pnpm -C packages/sui test        # unit + fixture; the testnet suite skips loudly without keys
pnpm -C packages/sui typecheck   # tsc, then the README gate against dist/ (build sweetrust first: run `pnpm build` at the root)
SWEETRUST_SUI_TESTNET_KEYS=/path/keys.json pnpm -C packages/sui test:testnet   # four real refusals
SWEETRUST_SUI_TESTNET_KEYS=… SWEETRUST_SUI_RECORD=1 pnpm -C packages/sui test:testnet   # and rewrite the fixture
```

Node ≥ 22 (because `@mysten/sui` needs it). The testnet principal needs SUI in its **address
balance** (allowances draw from it) plus gas; the agent needs gas.
