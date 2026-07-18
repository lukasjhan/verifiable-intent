/**
 * Verifiable Intent (VI) type definitions.
 *
 * Source: `agent-intent/verifiable-intent` spec v0.1-draft + Python reference.
 * On the wire every layer is a plain RFC 9901 SD-JWT string (`<jwt>~<disclosure>~...~`).
 * Mandates are NOT top-level claims — they are array-element disclosures referenced from a
 * `delegate_payload` array as `{"...": <digest>}`.
 */

import type { VI_TYP, VI_VCT, CONSTRAINT_TYPE, STRICTNESS } from "./constants.js";

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** JSON Web Key (public), RFC 7517. Only the fields VI relies on are typed here. */
export interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  kid?: string;
  alg?: string;
  use?: string;
  [key: string]: unknown;
}

/** RFC 7800 confirmation claim. In VI, `cnf.jwk` names the key allowed to sign the NEXT layer. */
export interface Cnf {
  jwk: Jwk;
  kid?: string;
}

/** Base64url(SHA-256(...)) digest string. */
export type Sd256Hash = string;

export type Typ = (typeof VI_TYP)[keyof typeof VI_TYP];
export type Vct = (typeof VI_VCT)[keyof typeof VI_VCT] | (string & {});
export type ConstraintType = (typeof CONSTRAINT_TYPE)[keyof typeof CONSTRAINT_TYPE] | (string & {});
export type Strictness = (typeof STRICTNESS)[keyof typeof STRICTNESS];

/** An array-element reference to a disclosure: `{"...": <digest>}`. */
export interface DelegateRef {
  "...": Sd256Hash;
}

export interface JoseHeader {
  alg: "ES256";
  typ: Typ;
  kid?: string;
  /** Present in L3 headers but MUST NOT be trusted — resolve the key via the prior `cnf` (§10.4). */
  jwk?: Jwk;
  [key: string]: unknown;
}

/** A decoded disclosure. `key` is absent for array-element disclosures (`[salt, value]`). */
export interface Disclosure {
  salt: string;
  key?: string;
  value: unknown;
}

/**
 * A parsed VI layer: the compact SD-JWT plus its decoded header/payload and disclosures.
 * `disclosureStrings` are the verbatim base64url segments — hash and present over THESE so
 * bytes match across issuer and verifier.
 */
export interface ViLayer<Payload = Record<string, unknown>> {
  /** Compact serialization: `<base-jwt>~<disclosure>~...~` (trailing `~`, no appended KB-JWT). */
  readonly serialized: string;
  readonly header: JoseHeader;
  readonly payload: Payload;
  readonly disclosures: readonly Disclosure[];
  readonly disclosureStrings: readonly string[];
}

// ---------------------------------------------------------------------------
// Layer 1 — issuer → user (§3.1)
// ---------------------------------------------------------------------------

export interface L1Payload {
  iss: string;
  sub?: string;
  iat: number;
  exp: number;
  vct: Vct;
  aud?: string;
  /** RFC 7800 — the user's public key (root of authority). */
  cnf: Cnf;
  pan_last_four?: string;
  scheme?: string;
  card_id?: string;
  /** Object-property selective disclosure (folded in via `_sd`). */
  email?: string;
  _sd?: Sd256Hash[];
  _sd_alg?: "sha-256";
  [key: string]: unknown;
}

export type L1 = ViLayer<L1Payload>;

// ---------------------------------------------------------------------------
// Layer 2 — user → agent (§3.1, §3.3)
// ---------------------------------------------------------------------------

/** L2 top-level payload. Mandates live in disclosures, referenced by `delegate_payload`. */
export interface L2Payload {
  iat: number;
  exp?: number;
  iss?: string;
  /** Recipient of this delegation (the agent). */
  aud: string;
  nonce: string;
  /** B64U(SHA-256(ASCII(serialized_L1_as_received))). */
  sd_hash: Sd256Hash;
  prompt_summary?: string;
  delegate_payload: DelegateRef[];
  _sd?: Sd256Hash[];
  _sd_alg: "sha-256";
  [key: string]: unknown;
}

export type L2 = ViLayer<L2Payload>;

/** A merchant entry (standalone disclosure in Autonomous L2). */
export interface Merchant {
  id?: string;
  name?: string;
  website?: string;
  [key: string]: unknown;
}

/** An acceptable item entry (standalone disclosure in Autonomous L2). */
export interface Item {
  id?: string;
  sku?: string;
  title?: string;
  [key: string]: unknown;
}

/** Decoded checkout mandate (Immediate = final values; Autonomous = `open` + constraints). */
export interface CheckoutMandateDict {
  vct: Vct;
  cnf?: Cnf;
  constraints?: Constraint[];
  checkout_jwt?: string;
  checkout_hash?: Sd256Hash;
  [key: string]: unknown;
}

/** Decoded payment mandate. */
export interface PaymentMandateDict {
  vct: Vct;
  cnf?: Cnf;
  constraints?: Constraint[];
  payment_instrument?: PaymentInstrument;
  risk_data?: Record<string, unknown>;
  payee?: Payee;
  payment_amount?: PaymentAmount;
  transaction_id?: Sd256Hash;
  [key: string]: unknown;
}

export interface Payee {
  id?: string;
  name?: string;
  website?: string;
  [key: string]: unknown;
}

export interface PaymentAmount {
  currency: string;
  /** Integer minor units (cents). */
  amount: number;
}

export interface PaymentInstrument {
  type?: string;
  id?: string;
  description?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Layer 3 — agent → verifier, split (§3.1, §4)
// ---------------------------------------------------------------------------

export interface L3Payload {
  iat: number;
  exp?: number;
  iss?: string;
  aud: string;
  nonce: string;
  /** Selective sd_hash over the recipient's L2 view (§5.4). */
  sd_hash: Sd256Hash;
  delegate_payload: DelegateRef[];
  _sd_alg: "sha-256";
  /** Terminal delegation — MUST NOT contain `cnf` (§10.4). */
  cnf?: never;
  [key: string]: unknown;
}

export type L3Payment = ViLayer<L3Payload>;
export type L3Checkout = ViLayer<L3Payload>;

export interface FinalPaymentMandateDict {
  vct: Vct;
  transaction_id: Sd256Hash;
  payee: Payee;
  payment_amount: PaymentAmount;
  payment_instrument: PaymentInstrument;
  [key: string]: unknown;
}

export interface FinalCheckoutMandateDict {
  vct: Vct;
  checkout_jwt: string;
  checkout_hash: Sd256Hash;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Constraints (Autonomous L2 only; constraints.md §4) — field names match the reference.
// ---------------------------------------------------------------------------

export interface AllowedMerchantsConstraint {
  type: typeof CONSTRAINT_TYPE.ALLOWED_MERCHANTS;
  /** Merchant objects, or `{"...": digest}` refs to standalone merchant disclosures. */
  allowed: Array<Merchant | DelegateRef>;
}

export interface LineItemEntry {
  id: string;
  acceptable_items: Array<Item | DelegateRef>;
  quantity: number;
  [key: string]: unknown;
}

export interface LineItemsConstraint {
  type: typeof CONSTRAINT_TYPE.LINE_ITEMS;
  items: LineItemEntry[];
  match_mode?: "minimum" | "exact";
}

export interface AllowedPayeesConstraint {
  type: typeof CONSTRAINT_TYPE.ALLOWED_PAYEES;
  allowed: Array<Merchant | DelegateRef>;
}

export interface AmountRangeConstraint {
  type: typeof CONSTRAINT_TYPE.AMOUNT_RANGE;
  currency: string;
  min?: number;
  max?: number;
}

export interface BudgetConstraint {
  type: typeof CONSTRAINT_TYPE.BUDGET;
  currency: string;
  /** Cumulative cap (minor units) — network-enforced (stateful). */
  max: number;
  min?: number;
}

export interface RecurrenceConstraint {
  type: typeof CONSTRAINT_TYPE.RECURRENCE;
  frequency: string;
  start_date: string;
  end_date?: string;
  number?: number;
}

export interface AgentRecurrenceConstraint {
  type: typeof CONSTRAINT_TYPE.AGENT_RECURRENCE;
  frequency: string;
  start_date: string;
  end_date: string;
  max_occurrences?: number;
}

export interface ReferenceConstraint {
  type: typeof CONSTRAINT_TYPE.REFERENCE;
  conditional_transaction_id: Sd256Hash;
}

export type Constraint =
  | AllowedMerchantsConstraint
  | LineItemsConstraint
  | AllowedPayeesConstraint
  | AmountRangeConstraint
  | BudgetConstraint
  | RecurrenceConstraint
  | AgentRecurrenceConstraint
  | ReferenceConstraint
  | { type: ConstraintType; [key: string]: unknown };

// ---------------------------------------------------------------------------
// Verification results
// ---------------------------------------------------------------------------

/** Result of {@link import("./constraints/index.js").checkConstraints}. */
export interface ConstraintCheckResult {
  satisfied: boolean;
  violations: string[];
  checked: string[];
  skipped: string[];
}

export interface VerificationResult {
  valid: boolean;
  errors: string[];
  mode?: "IMMEDIATE" | "AUTONOMOUS";
  checksPerformed: string[];
  checksSkipped: string[];
  l1Claims?: Record<string, unknown>;
  l2Claims?: Record<string, unknown>;
  l3PaymentClaims?: Record<string, unknown>;
  l3CheckoutClaims?: Record<string, unknown>;
}

