/**
 * sweetrust-sui — SweeTrust's Sui adapter.
 *
 * Delegated spending on Sui's native allowance (`0x2::allowance`), behind the
 * chain-agnostic interface of ADR 0003. Every receipt labels each limit `chain`
 * or `library` and says, in plain English, why a spend was refused.
 */
export { suiAllowances, enforces } from "./sui.ts"
export type { SuiAllowance, SuiAllowanceClient, SuiAllowances, SuiAllowancesOptions, ReceiptAppender } from "./sui.ts"
export { SUI, baseUnitsOf, defineScale } from "./scale.ts"
export type { Scale } from "./scale.ts"
export { ABORTS as SUI_ALLOWANCE_ABORTS } from "./allowance-move.ts"
export type {
  AllowanceAdapter, AllowanceLimits, AllowanceReceipt, AuthorizedBy, Caip2, DelegatedAllowance, Enforcement, HeldBy,
  LimitLine, LimitName, LimitVerdict, NativeAbort, RateLimit, Refusal, RefusalCode, Remaining, Verb,
} from "./interface.ts"
