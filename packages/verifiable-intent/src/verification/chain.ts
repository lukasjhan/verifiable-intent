/**
 * Delegation-chain verification (§5.3, §10.4) — a faithful single-mandate-pair port of the
 * reference `verification/chain.py`. (Multi-pair L2 is a TODO; see the reference `split_l3s`.)
 *
 * Verifiers only ever hold the layers routed to them (§7):
 *   Immediate            → L1 + L2
 *   Autonomous merchant  → L1 + L2 (checkout view) + L3b
 *   Autonomous network   → L1 + L2 (payment view)  + L3a
 * L1 + L2 are always required; no single verifier needs BOTH L3 legs (dispute resolution aside).
 */
import { DEFAULT_CLOCK_SKEW_SECONDS, VI_TYP, VI_VCT } from "../constants.js";
import type {
  Constraint,
  ConstraintCheckResult,
  Jwk,
  L1,
  L2,
  L3Checkout,
  L3Payment,
  Strictness,
  VerificationResult,
} from "../types.js";
import { baseJwtOf, verifySignature } from "../crypto/sd-jwt.js";
import { sha256 } from "../crypto/hash.js";
import { delegateRefHash, hashDisclosure, resolveDisclosures } from "../crypto/disclosure.js";
import { checkConstraints } from "../constraints/index.js";

const CHECKOUT_VCTS = new Set<string>([VI_VCT.CHECKOUT_OPEN, VI_VCT.CHECKOUT_FINAL]);
const PAYMENT_VCTS = new Set<string>([VI_VCT.PAYMENT_OPEN, VI_VCT.PAYMENT_FINAL]);

export interface VerifyChainParams {
  l1: L1;
  l2: L2;
  l3Payment?: L3Payment;
  l3Checkout?: L3Checkout;
  /** Resolves an issuer `kid` to a public JWK via JWKS (§3.1 — `iss` + `kid`, not `/.well-known`). */
  resolveIssuerKey: (iss: string, kid?: string) => Promise<Jwk>;
  /** Current unix time (seconds); injected for testability. */
  now: number;
  clockSkewSeconds?: number;
  strictness?: Strictness;
  /** L1/L2 serializations as presented (default: the layers' own `.serialized`). */
  l1Serialized?: string;
  l2Serialized?: string;
  /** The L2 presentation each L3 recipient saw, for selective `sd_hash` (default: full L2). */
  l2PaymentSerialized?: string;
  l2CheckoutSerialized?: string;
  expectedL1Vct?: string;
}

interface Ctx {
  result: VerificationResult;
  now: number;
  skew: number;
}

/** Verify a VI delegation chain. Returns a structured result (fails fast, like the reference). */
export async function verifyChain(params: VerifyChainParams): Promise<VerificationResult> {
  const result: VerificationResult = { valid: false, errors: [], checksPerformed: [], checksSkipped: [] };
  const ctx: Ctx = { result, now: params.now, skew: params.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS };
  const fail = (msg: string) => {
    result.errors.push(msg);
    return result;
  };

  const { l1, l2 } = params;
  const l1Ser = params.l1Serialized ?? l1.serialized;
  const l2Ser = params.l2Serialized ?? l2.serialized;

  // 1. L1 header + signature.
  if (l1.header.typ !== VI_TYP.L1) return fail(`L1 typ must be ${VI_TYP.L1}`);
  if (l1.header.alg !== "ES256") return fail("L1 alg must be ES256");
  const issuerKey = await params.resolveIssuerKey(l1.payload.iss, l1.header.kid);
  if (!(await verifySignature(baseJwtOf(l1Ser), issuerKey))) return fail("L1 signature verification failed");

  // 1a. L1 vct + _sd_alg + expiry.
  const expectedVct = params.expectedL1Vct ?? VI_VCT.L1_CARD;
  if (l1.payload.vct !== expectedVct) return fail(`L1 vct must be '${expectedVct}', got '${l1.payload.vct}'`);
  if (l1.payload._sd_alg && l1.payload._sd_alg !== "sha-256") return fail("L1 _sd_alg must be sha-256");
  if (expired(l1.payload.exp, ctx)) return fail("L1 credential expired");
  if (futureDated(l1.payload.iat, ctx)) return fail("L1 iat is in the future");
  result.l1Claims = await resolveDisclosures(l1.payload, l1.disclosureStrings);

  // 2. Extract user key from L1 cnf; verify L2 signature.
  const userJwk = l1.payload.cnf?.jwk;
  if (!userJwk) return fail("L1 missing cnf.jwk (user public key)");
  if (!(await verifySignature(baseJwtOf(l2Ser), userJwk))) return fail("L2 signature verification failed");

  // 2a. L2 sd_hash binds to presented L1; _sd_alg; expiry.
  if (!l2.payload.sd_hash) return fail("L2 missing required sd_hash binding to L1");
  if (l2.payload.sd_hash !== (await sha256(l1Ser))) return fail("L2 sd_hash does not match L1 serialized form");
  if (l2.payload._sd_alg && l2.payload._sd_alg !== "sha-256") return fail("L2 _sd_alg must be sha-256");
  if (futureDated(l2.payload.iat, ctx)) return fail("L2 iat is in the future");
  if (expired(l2.payload.exp, ctx)) return fail("L2 expired");
  result.l2Claims = await resolveDisclosures(l2.payload, l2.disclosureStrings);

  // 3. Pair the checkout + payment mandates from delegate_payload, and infer the mode.
  const pair = await extractMandatePair(l2, result.l2Claims);
  if ("error" in pair) return fail(pair.error);
  const { checkout, payment, checkoutDiscB64 } = pair;

  const isAutonomous =
    checkout?.vct === VI_VCT.CHECKOUT_OPEN || payment?.vct === VI_VCT.PAYMENT_OPEN;
  const hasFinal = checkout?.vct === VI_VCT.CHECKOUT_FINAL || payment?.vct === VI_VCT.PAYMENT_FINAL;
  if (isAutonomous && hasFinal) return fail("L2 mixes open (autonomous) and final (immediate) mandates");
  result.mode = isAutonomous ? "AUTONOMOUS" : "IMMEDIATE";

  const expectedL2Typ = isAutonomous ? VI_TYP.KB_SD_JWT_KB : VI_TYP.KB_SD_JWT;
  if (l2.header.typ !== expectedL2Typ) return fail(`L2 typ must be '${expectedL2Typ}', got '${l2.header.typ}'`);
  const hasL3 = !!(params.l3Payment || params.l3Checkout);
  if (!isAutonomous && hasL3) return fail("L3 provided but L2 is immediate-mode (final) only");

  // 4. Per-mode mandate validation.
  const mandateErr = await verifyMandatePair(checkout, payment, checkoutDiscB64, isAutonomous, ctx);
  if (mandateErr) return fail(mandateErr);

  if (!isAutonomous) {
    result.valid = true;
    return result;
  }

  // 5. Autonomous: extract agent key, verify each L3 leg.
  const agentJwk = (checkout?.cnf?.jwk ?? payment?.cnf?.jwk) as Jwk | undefined;
  if (!agentJwk) return fail("L2 open mandates missing cnf.jwk for agent delegation");
  const agentKid = agentJwk.kid;

  for (const [l3, label, viewSer, requiredVct] of [
    [params.l3Payment, "L3a (payment)", params.l2PaymentSerialized ?? l2Ser, VI_VCT.PAYMENT_FINAL],
    [params.l3Checkout, "L3b (checkout)", params.l2CheckoutSerialized ?? l2Ser, VI_VCT.CHECKOUT_FINAL],
  ] as const) {
    if (!l3) continue;
    const err = await verifyL3(l3, label, viewSer, requiredVct, agentJwk, agentKid, payment ?? null, ctx);
    if (err) return fail(err);
  }

  // 5b. Cross-reference when both legs are present.
  if (params.l3Payment && params.l3Checkout) {
    const tid = mandateFieldFromClaims(result.l3PaymentClaims, VI_VCT.PAYMENT_FINAL, "transaction_id");
    const chash = mandateFieldFromClaims(result.l3CheckoutClaims, VI_VCT.CHECKOUT_FINAL, "checkout_hash");
    if (tid !== chash) return fail(`L3 cross-reference mismatch: transaction_id=${tid} != checkout_hash=${chash}`);
    result.checksPerformed.push("l3_cross_reference");
  } else if (params.l3Payment || params.l3Checkout) {
    result.checksSkipped.push("l3_cross_reference (requires both L3a and L3b)");
  }

  // 6. Constraints (network side: payment constraints vs L3a fulfillment).
  if (params.l3Payment && payment?.constraints) {
    const fulfillment = buildPaymentFulfillment(result.l3PaymentClaims, payment.constraints, result.l2Claims);
    const cres = checkConstraints(payment.constraints as Constraint[], fulfillment, {
      mode: params.strictness,
      isOpenMandate: payment.vct === VI_VCT.PAYMENT_OPEN,
    });
    recordConstraints(result, cres);
    if (!cres.satisfied) return fail(`Constraint violation: ${cres.violations.join("; ")}`);
  }

  result.valid = true;
  return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function expired(exp: unknown, ctx: Ctx): boolean {
  if (exp === undefined || exp === null) return false;
  if (typeof exp !== "number" || !Number.isFinite(exp)) return true;
  return ctx.now > exp + ctx.skew;
}

function futureDated(iat: unknown, ctx: Ctx): boolean {
  if (iat === undefined || iat === null) return false;
  if (typeof iat !== "number" || !Number.isFinite(iat)) return true;
  return iat > ctx.now + ctx.skew;
}

interface MandatePair {
  checkout?: Record<string, any>;
  payment?: Record<string, any>;
  checkoutDiscB64?: string;
}

/** Pair the checkout + payment mandates from L2 `delegate_payload`, carrying the checkout disc b64. */
async function extractMandatePair(l2: L2, l2Claims: Record<string, unknown>): Promise<MandatePair | { error: string }> {
  const rawDelegates = Array.isArray(l2.payload.delegate_payload) ? l2.payload.delegate_payload : [];
  const resolved = Array.isArray(l2Claims["delegate_payload"]) ? (l2Claims["delegate_payload"] as unknown[]) : [];
  if (resolved.length === 0) return { error: "L2 delegate_payload resolved zero mandate disclosures" };

  // hash → raw disclosure string, so we can recover the checkout disclosure b64 for ref binding.
  const byHash = new Map<string, string>();
  for (const s of l2.disclosureStrings) byHash.set(await hashDisclosure(s), s);

  const pair: MandatePair = {};
  for (let i = 0; i < resolved.length; i++) {
    const m = resolved[i];
    if (typeof m !== "object" || m === null) continue;
    const vct = (m as Record<string, unknown>)["vct"];
    const refHash = delegateRefHash(rawDelegates[i]);
    if (typeof vct === "string" && CHECKOUT_VCTS.has(vct)) {
      pair.checkout = m as Record<string, any>;
      if (refHash) pair.checkoutDiscB64 = byHash.get(refHash);
    } else if (typeof vct === "string" && PAYMENT_VCTS.has(vct)) {
      pair.payment = m as Record<string, any>;
    }
  }
  if (!pair.checkout && !pair.payment) return { error: "L2 delegate_payload resolved zero mandate disclosures" };
  return pair;
}

async function verifyMandatePair(
  checkout: Record<string, any> | undefined,
  payment: Record<string, any> | undefined,
  checkoutDiscB64: string | undefined,
  isAutonomous: boolean,
  ctx: Ctx,
): Promise<string | null> {
  if (!isAutonomous) {
    if (!checkout || !payment) return "Immediate mode requires both checkout and payment mandates";
    if ("cnf" in checkout || "cnf" in payment) return "Immediate mode mandates must not contain cnf";
    for (const field of ["checkout_jwt", "checkout_hash"]) {
      if (!checkout[field]) return `Closed checkout mandate missing required field: ${field}`;
    }
    // checkout_hash == SHA-256(checkout_jwt); transaction_id == checkout_hash.
    const computed = await sha256(String(checkout["checkout_jwt"]));
    if (computed !== checkout["checkout_hash"]) return "checkout_hash != SHA-256(checkout_jwt)";
    if (payment["transaction_id"] !== checkout["checkout_hash"]) return "transaction_id != checkout_hash";
    ctx.result.checksPerformed.push("l2_checkout_payment_binding");
    return null;
  }

  // Autonomous: structural checks on open mandates + reference binding.
  if (checkout?.vct === VI_VCT.CHECKOUT_OPEN) {
    const hasLineItems = (checkout["constraints"] ?? []).some(
      (c: any) => c?.type === "mandate.checkout.line_items",
    );
    if (!hasLineItems) return "Open checkout mandate must contain a mandate.checkout.line_items constraint";
  }
  if (payment?.vct === VI_VCT.PAYMENT_OPEN) {
    const constraints = (payment["constraints"] ?? []) as any[];
    if (!constraints.some((c) => c?.type === "mandate.payment.reference"))
      return "Open payment mandate must contain a mandate.payment.reference constraint";
    const pi = payment["payment_instrument"];
    if (!pi || !pi.id || !pi.type) return "Open payment mandate missing payment_instrument (id + type)";
  }
  if (checkout && payment) {
    if (!checkoutDiscB64) return "L2 checkout disclosure string missing (required for reference binding)";
    const ref = ((payment["constraints"] ?? []) as any[]).find((c) => c?.type === "mandate.payment.reference");
    const expected = ref?.conditional_transaction_id;
    if (expected && expected !== (await hashDisclosure(checkoutDiscB64)))
      return "L2 reference binding failed: conditional_transaction_id != hash(checkout disclosure)";
    ctx.result.checksPerformed.push("l2_reference_binding");
  }
  return null;
}

async function verifyL3(
  l3: L3Payment | L3Checkout,
  label: string,
  viewSer: string,
  requiredVct: string,
  agentJwk: Jwk,
  agentKid: string | undefined,
  l2Payment: Record<string, any> | null,
  ctx: Ctx,
): Promise<string | null> {
  if ("cnf" in l3.payload) return `${label} payload MUST NOT contain cnf`;
  if (!(await verifySignature(baseJwtOf(l3.serialized), agentJwk))) return `${label} signature failed (agent key mismatch)`;
  if (l3.header.typ !== VI_TYP.KB_SD_JWT) return `${label} typ must be ${VI_TYP.KB_SD_JWT}`;
  if (!l3.payload.sd_hash) return `${label} missing required sd_hash binding to L2`;
  if (l3.payload.sd_hash !== (await sha256(viewSer))) return `${label} sd_hash does not match L2 view`;

  const kid = l3.header.kid;
  if (!kid) return `${label} header missing required kid`;
  if (agentKid && kid !== agentKid) return `${label} header kid '${kid}' != L2 cnf.jwk.kid '${agentKid}'`;

  if (futureDated(l3.payload.iat, ctx)) return `${label} iat is in the future`;
  if (expired(l3.payload.exp, ctx)) return `${label} expired`;
  const { iat, exp } = l3.payload;
  if (typeof iat === "number" && typeof exp === "number" && exp - iat > 3600)
    return `${label} exp MUST NOT exceed 1 hour from iat`;

  const claims = await resolveDisclosures(l3.payload, l3.disclosureStrings);
  if (requiredVct === VI_VCT.PAYMENT_FINAL) {
    ctx.result.l3PaymentClaims = claims;
    const err = validatePaymentMandate(claims, l2Payment, label);
    if (err) return err;
  } else {
    ctx.result.l3CheckoutClaims = claims;
    const mandate = mandateFromClaims(claims, VI_VCT.CHECKOUT_FINAL);
    if (!mandate) return `${label} missing required checkout mandate (${VI_VCT.CHECKOUT_FINAL})`;
    for (const f of ["checkout_jwt", "checkout_hash"]) if (!mandate[f]) return `${label} checkout mandate missing ${f}`;
  }
  ctx.result.checksPerformed.push(`${label} structural_chain`);
  return null;
}

function validatePaymentMandate(
  claims: Record<string, unknown>,
  l2Payment: Record<string, any> | null,
  label: string,
): string | null {
  const m = mandateFromClaims(claims, VI_VCT.PAYMENT_FINAL);
  if (!m) return `${label} missing required payment mandate (${VI_VCT.PAYMENT_FINAL})`;
  if (!isNonEmptyStr(m["transaction_id"])) return `${label} payment mandate missing transaction_id`;
  const payee = m["payee"];
  if (!payee || typeof payee !== "object") return `${label} payment mandate payee must be an object`;
  if (!isNonEmptyStr((payee as any).name) || !isNonEmptyStr((payee as any).website))
    return `${label} payee missing name/website`;
  const pa = m["payment_amount"];
  if (!pa || typeof pa !== "object" || !isNonEmptyStr((pa as any).currency) || !Number.isInteger((pa as any).amount))
    return `${label} payment_amount missing currency/integer amount`;
  const pi = m["payment_instrument"];
  if (!pi || !isNonEmptyStr((pi as any).id) || !isNonEmptyStr((pi as any).type))
    return `${label} payment_instrument missing id/type`;
  // Cross-check L3 payment_instrument against L2 authorized value.
  const l2pi = l2Payment?.["payment_instrument"];
  if (l2pi && ((pi as any).id !== l2pi.id || (pi as any).type !== l2pi.type))
    return `${label} payment_instrument does not match L2 authorized value`;
  return null;
}

function mandateFromClaims(claims: Record<string, unknown>, vct: string): Record<string, any> | null {
  const delegates = Array.isArray(claims["delegate_payload"]) ? (claims["delegate_payload"] as unknown[]) : [];
  for (const d of delegates) if (d && typeof d === "object" && (d as any).vct === vct) return d as Record<string, any>;
  return null;
}

function mandateFieldFromClaims(claims: Record<string, unknown> | undefined, vct: string, field: string): unknown {
  if (!claims) return undefined;
  return mandateFromClaims(claims, vct)?.[field];
}

/** Build the network-side fulfillment object from L3a claims + resolved L2 allowed merchants. */
function buildPaymentFulfillment(
  l3PaymentClaims: Record<string, unknown> | undefined,
  constraints: Constraint[],
  l2Claims: Record<string, unknown>,
): Record<string, unknown> {
  const m = l3PaymentClaims ? mandateFromClaims(l3PaymentClaims, VI_VCT.PAYMENT_FINAL) : null;
  const fulfillment: Record<string, unknown> = { ...(m ?? {}) };
  // Resolve allowed_payees refs (already resolved to merchant objects by getClaims) into a flat list.
  const payees = (constraints as any[]).find((c) => c?.type === "mandate.payment.allowed_payees");
  if (payees && Array.isArray(payees.allowed)) {
    fulfillment["allowed_merchants"] = payees.allowed.filter((x: unknown) => x && typeof x === "object" && delegateRefHash(x) === null);
  }
  void l2Claims;
  return fulfillment;
}

function recordConstraints(result: VerificationResult, cres: ConstraintCheckResult): void {
  result.checksPerformed.push(...cres.checked.map((c) => `constraint:${c}`));
  result.checksSkipped.push(...cres.skipped.map((c) => `constraint:${c}`));
}

function isNonEmptyStr(v: unknown): boolean {
  return typeof v === "string" && v.trim() !== "";
}
