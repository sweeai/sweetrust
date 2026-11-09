/**
 * sweetrust — the owner's purpose, as a types-only leaf.
 *
 * A purpose is written by the owner, signed into the grant event by
 * `sweetrust/mandate`, and read by a judged sink in `sweetrust/gate`. Both
 * import these types from here, so the gate still does not import the mandate
 * module (each subpath stands alone; see `src/index.ts`). This file has no
 * runtime content; the checks live in `src/mandate/mandate.ts`.
 */

/**
 * Purpose — what a grant is for.
 *
 * `statement` is the owner's sentence, at most 280 characters, taken as
 * written. `fields` are the deterministic parts, each optional and each only
 * ever narrowed by delegation: `payees` and `actions` (sink names) are
 * byte-compared lists, and `maxPerAction` is an integer in decimal base units,
 * held as a string so the grant signs cleanly. Cumulative caps stay in
 * `limits`.
 */
export interface Purpose {
  readonly statement: string
  readonly fields?: {
    readonly payees?: ReadonlyArray<string>
    readonly maxPerAction?: string
    readonly actions?: ReadonlyArray<string>
  }
}

/**
 * GrantedPurpose — a purpose together with the grant that signs it.
 * `grantHash` is `sha256Hex(canonicalJSON(grantEvent))`.
 */
export interface GrantedPurpose {
  readonly purpose: Purpose
  readonly grantHash: string
}
