# The cap held by Sui itself, on a real testnet wallet

The same "send everything" attack as [`spending-cap`](../spending-cap), but the limit is not a library check. The owner opens an **allowance** with Sui's own `0x2::allowance` module (a rate limit of 0.02 SUI a day), and the agent's key can only spend through it. An over-cap spend is built so that it executes, aborts inside Sui, and leaves a failed transaction with a digest anyone can open.

**Testnet only.** Every SUI here is test money. The script refuses to sign unless the chain is the testnet.

## Run it

You need three testnet keys, and two of them funded: the owner wallet and the agent's key (it pays gas for every spend it signs). From an empty folder, on Node 22.18 or later:

```bash
npm i sweetrust@0.7.0 sweetrust-sui@0.1.0 @mysten/sui@^2.35.0
curl -fsSLO https://raw.githubusercontent.com/sweeai/sweetrust/main/examples/sui-cap/drain.ts
curl -fsSLO https://raw.githubusercontent.com/sweeai/sweetrust/main/examples/sui-cap/make-keys.ts
node make-keys.ts      # writes keys.json (testnet only) and prints the two addresses to fund
```

Fund both printed addresses with the Sui CLI (`sui client faucet --address <address>`) or at <https://faucet.sui.io> (choose Testnet), then:

```bash
node drain.ts --rehearse
```

From a clone of this repository: `cd examples/sui-cap && npm install && node make-keys.ts`, fund both, then `node drain.ts --rehearse`. A run takes about 15 seconds and costs a few thousandths of a testnet SUI in gas.

`--rehearse` is the same run followed by a cleanup (revoke the allowance, sweep the attacker's SUI back), so the next run starts where this one did. `--sweep` is the cleanup alone. Set `SWEETRUST_SUI_TESTNET_KEYS` to use a keys file elsewhere.

**About the keys.** `keys.json` holds three secret keys in plain text. Keep it out of any git repository (this repository's `.gitignore` covers it; a folder you made yourself has none), and never point `SWEETRUST_SUI_TESTNET_KEYS` at a key that holds real funds. The script checks it is talking to the testnet before it signs, and the checks should never be your only protection.

## What is real and what is a stand-in

- **Real:** the owner's wallet, the allowance, the four spends the agent signs, and the transactions on the testnet. The refusals are Sui's own `EExceedsRateLimit` aborts, the spends are listed back by the chain's own indexer, and the verdict is computed from those results and the chain's balances.
- **sweetrust-sui** builds the spends, reads the allowance and explains each refusal. It is the published `sweetrust-sui` 0.1.0.
- **Stand-in:** the agent. Its four proposals are scripted, and the attacker is an address you control.

## What you will see

```text
  open · the owner gives the agent an allowance of 0.02 SUI a day → OPENED
  1 · agent tries to send everything (2.29 SUI) → REFUSED BY SUI (EExceedsRateLimit)
  2 · agent tries to send 0.02 SUI → SENT
  3 · agent tries to send 0.02 SUI more → REFUSED BY SUI (EExceedsRateLimit)
  4 · agent tries to send 0.001 SUI → REFUSED BY SUI (EExceedsRateLimit)
  audit · the chain's own indexer lists 4 spend attempts: 1 succeeded (0.02 SUI), 3 failed
ATTACK 9 · sui drain · BLOCKED by the chain
```

Each step also prints a transaction digest and a suiscan link. Your amounts differ with your balance. With `--rehearse`, the cleanup lines (revoke, sweep) print just before the verdict.

## What it does not do

Whoever holds the agent key can still spend up to the cap, to any address, because the chain does not limit the recipient. Only the owner's revoke stops that. Sui's rate window is fixed, not rolling. `sweetrust-sui` 0.1.0 needs `@mysten/sui` 2.35 or later in the 2.x line (not yet 3.x).
