# An allow list and a records check, in front of one payment

An agent pays contractor invoices for an owner. Three layers each answer one question: the **cap** (how much), the **allow list** (who) and a **records check** (what for). Two attacks try to slip past them: a payment to a new wallet, and a payment to a saved contractor that matches no invoice at all.

## Run it

From an empty folder, on Node 22.18 or later:

```bash
npm i sweetrust@0.7.0 && curl -fsSLO https://raw.githubusercontent.com/sweeai/sweetrust/main/examples/allow-list-and-records/layers.ts && node layers.ts
```

From a clone of this repository: `cd examples/allow-list-and-records && npm install && npm start`.

It runs offline and takes under a second: no network after the install, no keys, **no model**.

Extra checks: `--liar` (the attack's memo claims to be the invoice), `--ben` (a second real invoice still pays), `--two` (two unpaid invoices for one contractor both pay), `--replay` (the same invoice paid again is stopped), `--break-records` (the check fails, and the run says it could not run).

## Who decides what

| Piece | Who decides |
|---|---|
| The cap | **Real sweetrust** (`sweetrust/mandate`): a limit on the agent's mandate. **The sink does not check it.** This script asks the cap first and obeys its answer, the way a host does, so a host that skipped the call would not be stopped by the sink. |
| The allow list | **Real sweetrust.** The owner's signed purpose carries `fields.payees`, and the sink refuses any other payee before the records check runs. The `allow list:` line is built from the receipt and refusal text the sink returns, not from the script's own list. |
| The records check | **Script code**, about 12 lines, plugged into the sink's `judgment` option. It looks the payment up in the owner's invoices: is it an unpaid invoice, from a saved contractor, for the same amount? That is a lookup, so **there is no model, and the check has no confidence figure**. It never reads the agent's memo. |
| The receipt | **Real sweetrust.** Each `receipt:` line is the library's own decision: `executed`, `refused`, `judgment-blocked`, `judgment-held` or `errored`. |
| Invoice records, address book, ledger | **Stand-ins** for the owner's bookkeeping and a payment rail. |

The agent's payee, amount and memo are marked untrusted, because nothing has verified them. The allow list and the records check decide.

## What you will see

```text
control · pay a saved contractor's invoice
  allow list:  Ana (design), on the list (SweeTrust passed the payee)
  records:     MATCH · INV-ANA-NOV is on file, unpaid, Ana (design), $3,000
  receipt:     executed
  result:      PAID · Ana (design) received $3,000

attack 2a · the attacker talks the agent into paying a NEW wallet
  allow list:  NOT ON THE LIST · REFUSED by SweeTrust (to is not a payee this purpose names)
  records:     not checked (SweeTrust refused the payment before the check: …)
  receipt:     refused
  result:      REFUSED, nothing paid · the new wallet holds $0

attack 2b · the attacker stays on the allow list
  records:     NO MATCH · no invoice on file for Ana (design) at $6,500
  receipt:     judgment-blocked
  result:      BLOCKED, nothing paid · Ana (design) holds $3,000 in all (the invoice alone was $3,000)

ATTACK 8 · layers · BLOCKED by the allow list and the records check
```

(Trimmed; run it for every line.) If the records check cannot answer, the run ends `COULD NOT RUN` and nothing is paid.

## Ways it can still be fooled

- **A forged record.** If an attacker gets an invoice filed into the owner's records, the check sees an unpaid invoice and the payment runs. The check is only as trustworthy as whatever writes the records.
- **An inflated invoice.** An invoice that is on file but wrong still matches. The check proves "this is an invoice on file", never "the invoice is right".
- **Partial payments are blocked.** Half of an invoice matches no record, so it stops. That is safe, and a real owner needs a way to approve it.
- **The records here live in memory**, so a restart forgets what was paid. A real deployment persists them.
