/**
 * Verifiable Intent (VI) protocol constants.
 *
 * Source: `agent-intent/verifiable-intent` spec v0.1-draft (Verifiable Intent Working Group).
 * Section references (§) point to the spec `spec/` directory.
 */

/** Required signing algorithm across every layer (§6, design-rationale §). ES256 = P-256 ECDSA. */
export const VI_ALG = "ES256" as const;

/**
 * `typ` header values, one per layer/mode (spec appendix "typ 값 일람").
 *
 * NOTE (KB-SD-JWT structure): despite the "kb-sd-jwt" naming, VI layers do NOT append a
 * separate trailing KB-JWT segment the way vanilla RFC 9901 does. Each layer is a single
 * signed SD-JWT whose key-binding claims (`sd_hash`, `nonce`, `aud`, `iat`) live IN its
 * payload, and "key binding" is expressed by signing the layer with the key named in the
 * previous layer's `cnf`. The `+kb` suffix means the payload additionally carries a `cnf`
 * for the NEXT delegation (Autonomous L2 → agent key).
 */
export const VI_TYP = {
  /** L1 — issuer → user root credential. */
  L1: "sd+jwt",
  /** L2 Immediate, and both L3a / L3b. */
  KB_SD_JWT: "kb-sd-jwt",
  /** L2 Autonomous — carries an onward `cnf` (agent key). */
  KB_SD_JWT_KB: "kb-sd-jwt+kb",
} as const;

/** `vct` values seen in the Mastercard reference profile (spec appendix "vct 값 일람"). */
export const VI_VCT = {
  L1_CARD: "https://credentials.mastercard.com/card",
  CHECKOUT_OPEN: "mandate.checkout.open.1",
  PAYMENT_OPEN: "mandate.payment.open.1",
  CHECKOUT_FINAL: "mandate.checkout.1",
  PAYMENT_FINAL: "mandate.payment.1",
} as const;

/** The eight constraint types, valid only inside Autonomous L2 mandates (constraints.md §4). */
export const CONSTRAINT_TYPE = {
  ALLOWED_MERCHANTS: "mandate.checkout.allowed_merchants",
  LINE_ITEMS: "mandate.checkout.line_items",
  ALLOWED_PAYEES: "mandate.payment.allowed_payees",
  AMOUNT_RANGE: "mandate.payment.amount_range",
  BUDGET: "mandate.payment.budget",
  RECURRENCE: "mandate.payment.recurrence",
  AGENT_RECURRENCE: "mandate.payment.agent_recurrence",
  REFERENCE: "mandate.payment.reference",
} as const;

/**
 * Constraints whose enforcement requires cross-transaction state (constraints.md §).
 * A stateless verifier cannot enforce these — the payment network must track cumulative state.
 */
export const NETWORK_ENFORCED_CONSTRAINTS = [
  CONSTRAINT_TYPE.BUDGET,
  CONSTRAINT_TYPE.RECURRENCE,
  CONSTRAINT_TYPE.AGENT_RECURRENCE,
] as const;

/** Strictness modes for unknown constraint types (constraints.md §5.4). Default MUST be PERMISSIVE. */
export const STRICTNESS = {
  /** Unknown types are skipped and recorded; known types must pass. */
  PERMISSIVE: "PERMISSIVE",
  /** Unknown types are an immediate violation; all must be recognized and pass. */
  STRICT: "STRICT",
} as const;

/** Recommended clock skew tolerance for expiry checks (§5.3). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 300;
