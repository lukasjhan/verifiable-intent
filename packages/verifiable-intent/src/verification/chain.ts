/**
 * Delegation-chain verification (§5.3, §10.4) — a faithful port of the reference
 * `verification/chain.py`, including MULTI mandate-pair L2 (one L2 authorizing several
 * checkout+payment pairs).
 *
 * Verifiers only ever hold the layers routed to them (§7):
 *   Immediate            → L1 + L2
 *   Autonomous merchant  → L1 + L2 (checkout view) + L3b
 *   Autonomous network   → L1 + L2 (payment view)  + L3a
 * L1 + L2 are always required; no single verifier needs BOTH L3 legs (dispute resolution aside).
 *
 * NETWORK-ENFORCED constraints (`budget` / `recurrence` / `agent_recurrence`) require
 * cross-transaction state a stateless verifier cannot hold. They are NOT enforced here — a passing
 * result surfaces them in {@link VerificationResult.networkEnforced} for the caller to evaluate
 * against its own state. `valid: true` therefore means "stateless checks pass", not "budget ok".
 */
import { DEFAULT_CLOCK_SKEW_SECONDS, NETWORK_ENFORCED_CONSTRAINTS, VI_TYP, VI_VCT } from "../constants.js";
import type {
  Constraint,
  ConstraintCheckResult,
  ConstraintType,
  Jwk,
  L1,
  L2,
  L3Checkout,
  L3Payment,
  NetworkEnforcedConstraint,
  Strictness,
  VerificationResult,
} from "../types.js";
import { baseJwtOf, verifySignature } from "../crypto/sd-jwt.js";
import { sha256 } from "../crypto/hash.js";
import { delegateRefHash, hashDisclosure, resolveDisclosures } from "../crypto/disclosure.js";
import { checkConstraints } from "../constraints/index.js";

const CHECKOUT_VCTS = new Set<string>([VI_VCT.CHECKOUT_OPEN, VI_VCT.CHECKOUT_FINAL]);
const PAYMENT_VCTS = new Set<string>([VI_VCT.PAYMENT_OPEN, VI_VCT.PAYMENT_FINAL]);
const NETWORK_ENFORCED = new Set<string>(NETWORK_ENFORCED_CONSTRAINTS);

/** One split L3 (L3a + L3b) for a single mandate pair, with the L2 view each leg saw. */
export interface SplitL3 {
  l3Payment?: L3Payment;
  l3Checkout?: L3Checkout;
  l2PaymentSerialized?: string;
  l2CheckoutSerialized?: string;
}

export interface VerifyChainParams {
  l1: L1;
  l2: L2;
  /** Single-pair convenience (maps to mandate pair 0). Mutually exclusive with `splitL3s`. */
  l3Payment?: L3Payment;
  l3Checkout?: L3Checkout;
  l2PaymentSerialized?: string;
  l2CheckoutSerialized?: string;
  /** Multi-pair: one entry per mandate pair, positionally matched. */
  splitL3s?: SplitL3[];
  /** Resolves an issuer `kid` to a public JWK via JWKS (§3.1 — `iss` + `kid`, not `/.well-known`). */
  resolveIssuerKey: (iss: string, kid?: string) => Promise<Jwk>;
  /** Current unix time (seconds); injected for testability. */
  now: number;
  clockSkewSeconds?: number;
  strictness?: Strictness;
  /** L1/L2 serializations as presented (default: the layers' own `.serialized`). */
  l1Serialized?: string;
  l2Serialized?: string;
  expectedL1Vct?: string;
}

interface Ctx {
  result: VerificationResult;
  now: number;
  skew: number;
}

type Dict = Record<string, any>;
interface MandateEntry {
  resolved: Dict;
  refHash?: string;
  discB64?: string;
}
interface PairInfo {
  checkout?: Dict;
  payment?: Dict;
  checkoutDiscB64?: string;
  paymentDiscB64?: string;
}
interface PairResult {
  l3PaymentClaims?: Record<string, unknown>;
  l3CheckoutClaims?: Record<string, unknown>;
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

  // 3. Infer mode from mandate VCTs, then pair the checkout+payment mandates.
  const resolvedDelegates = Array.isArray(result.l2Claims["delegate_payload"])
    ? (result.l2Claims["delegate_payload"] as unknown[])
    : [];
  const mode = inferMode(resolvedDelegates);
  if ("error" in mode) return fail(mode.error);
  const isAutonomous = mode.isAutonomous;
  result.mode = isAutonomous ? "AUTONOMOUS" : "IMMEDIATE";

  const expectedL2Typ = isAutonomous ? VI_TYP.KB_SD_JWT_KB : VI_TYP.KB_SD_JWT;
  if (l2.header.typ !== expectedL2Typ) return fail(`L2 typ must be '${expectedL2Typ}', got '${l2.header.typ}'`);

  const extracted = await extractMandatePairs(l2, resolvedDelegates, isAutonomous);
  if ("error" in extracted) return fail(extracted.error);
  const pairs = extracted.pairs;
  result.mandatePairCount = pairs.length;

  // 3a. Mutual exclusion + presence checks on the provided L3 arguments.
  const singleL3 = !!(params.l3Payment || params.l3Checkout);
  if (params.splitL3s && singleL3) return fail("Provide either splitL3s or l3Payment/l3Checkout, not both");
  const hasL3 = singleL3 || !!params.splitL3s?.some((s) => s.l3Payment || s.l3Checkout);
  if (!isAutonomous && hasL3) return fail("L3 provided but L2 is immediate-mode (final) only");

  // 4. Per-pair mandate validation + card_id cross-check.
  for (let i = 0; i < pairs.length; i++) {
    const mandateErr = await verifyMandatePair(pairs[i]!, isAutonomous, ctx);
    if (mandateErr) return fail(`pair ${i}: ${mandateErr}`);
  }
  const cardErr = cardIdCrossCheck(l1, pairs, ctx);
  if (cardErr) return fail(cardErr);

  if (!isAutonomous) {
    result.valid = true;
    return result;
  }

  // 5. Autonomous: extract the (single) agent key shared across all pairs.
  const agent = extractAgentKey(pairs);
  if (agent.error) return fail(agent.error);
  if (!agent.jwk) return fail("L2 open mandates missing cnf.jwk for agent delegation");
  const { jwk: agentJwk, kid: agentKid } = agent;

  // 5a. Surface network-enforced constraints (caller must enforce statefully).
  result.networkEnforced = collectNetworkEnforced(pairs);

  // 6. Normalize split L3s and verify each pair's legs.
  const splits = normalizeSplits(params, pairs.length);
  if ("error" in splits) return fail(splits.error);
  result.pairResults = pairs.map(() => ({}) as PairResult);

  for (let i = 0; i < splits.list.length; i++) {
    const sp = splits.list[i]!;
    const pair = pairs[i]!;
    const pr = result.pairResults[i]!;

    if (sp.l3Payment) {
      const view = sp.l2PaymentSerialized ?? l2Ser;
      const bindErr = viewBinds(view, pair.paymentDiscB64, `pair ${i} L3a`);
      if (bindErr) return fail(bindErr);
      const err = await verifyL3(sp.l3Payment, `pair ${i} L3a (payment)`, view, VI_VCT.PAYMENT_FINAL, agentJwk, agentKid, pair.payment ?? null, ctx, pr);
      if (err) return fail(err);
    }
    if (sp.l3Checkout) {
      const view = sp.l2CheckoutSerialized ?? l2Ser;
      const bindErr = viewBinds(view, pair.checkoutDiscB64, `pair ${i} L3b`);
      if (bindErr) return fail(bindErr);
      const err = await verifyL3(sp.l3Checkout, `pair ${i} L3b (checkout)`, view, VI_VCT.CHECKOUT_FINAL, agentJwk, agentKid, pair.payment ?? null, ctx, pr);
      if (err) return fail(err);
    }

    // Cross-reference when both legs present.
    if (sp.l3Payment && sp.l3Checkout) {
      const tid = mandateFieldFromClaims(pr.l3PaymentClaims, VI_VCT.PAYMENT_FINAL, "transaction_id");
      const chash = mandateFieldFromClaims(pr.l3CheckoutClaims, VI_VCT.CHECKOUT_FINAL, "checkout_hash");
      if (tid !== chash) return fail(`pair ${i} L3 cross-reference mismatch: transaction_id=${tid} != checkout_hash=${chash}`);
      result.checksPerformed.push(`pair_${i}_l3_cross_reference`);
    } else if (sp.l3Payment || sp.l3Checkout) {
      result.checksSkipped.push(`pair_${i}_l3_cross_reference (requires both L3a and L3b)`);
    }

    // Constraints (network side): payment constraints vs L3a fulfillment.
    if (sp.l3Payment && pair.payment?.["constraints"]) {
      const fulfillment = buildPaymentFulfillment(pr.l3PaymentClaims, pair.payment["constraints"]);
      const cres = checkConstraints(pair.payment["constraints"] as Constraint[], fulfillment, {
        mode: params.strictness,
        isOpenMandate: pair.payment["vct"] === VI_VCT.PAYMENT_OPEN,
      });
      recordConstraints(result, cres);
      if (!cres.satisfied) return fail(`pair ${i} constraint violation: ${cres.violations.join("; ")}`);
    }
  }

  // 7. Back-compat: expose the first pair's L3 claims at the top level.
  const first = result.pairResults[0];
  if (first) {
    result.l3PaymentClaims = first.l3PaymentClaims;
    result.l3CheckoutClaims = first.l3CheckoutClaims;
  }

  result.valid = true;
  return result;
}

// ---------------------------------------------------------------------------
// Mode + pairing
// ---------------------------------------------------------------------------

function inferMode(resolvedDelegates: unknown[]): { isAutonomous: boolean } | { error: string } {
  let open = false;
  let final = false;
  for (const m of resolvedDelegates) {
    if (!m || typeof m !== "object") continue;
    const vct = (m as Dict)["vct"];
    if (vct === VI_VCT.CHECKOUT_OPEN || vct === VI_VCT.PAYMENT_OPEN) open = true;
    else if (vct === VI_VCT.CHECKOUT_FINAL || vct === VI_VCT.PAYMENT_FINAL) final = true;
  }
  if (open && final) return { error: "L2 mixes open (autonomous) and final (immediate) mandate VCTs" };
  return { isAutonomous: open };
}

async function extractMandatePairs(
  l2: L2,
  resolvedDelegates: unknown[],
  isAutonomous: boolean,
): Promise<{ pairs: PairInfo[] } | { error: string }> {
  const rawDelegates = Array.isArray(l2.payload.delegate_payload) ? l2.payload.delegate_payload : [];
  const byHash = new Map<string, string>();
  for (const s of l2.disclosureStrings) byHash.set(await hashDisclosure(s), s);

  const checkouts: MandateEntry[] = [];
  const payments: MandateEntry[] = [];
  const seenRefs = new Set<string>();

  for (let i = 0; i < resolvedDelegates.length; i++) {
    const m = resolvedDelegates[i];
    if (!m || typeof m !== "object") continue;
    const vct = (m as Dict)["vct"];
    const refHash = delegateRefHash(rawDelegates[i]) ?? undefined;
    if (refHash) {
      if (seenRefs.has(refHash))
        return { error: "L2 delegate_payload contains a duplicate disclosure reference (mandate smuggling)" };
      seenRefs.add(refHash);
    }
    const entry: MandateEntry = { resolved: m as Dict, refHash, discB64: refHash ? byHash.get(refHash) : undefined };
    if (typeof vct === "string" && CHECKOUT_VCTS.has(vct)) checkouts.push(entry);
    else if (typeof vct === "string" && PAYMENT_VCTS.has(vct)) payments.push(entry);
  }

  if (!checkouts.length && !payments.length) return { error: "L2 delegate_payload resolved zero mandate disclosures" };
  if (checkouts.length && payments.length) {
    return isAutonomous ? pairAutonomous(checkouts, payments) : pairImmediate(checkouts, payments);
  }
  if (!isAutonomous) return { error: "Immediate mode requires both checkout and payment mandate disclosures" };
  // Autonomous partial disclosure: single-sided pairs (a verifier that received only one side).
  const pairs = [
    ...checkouts.map((c) => toPair(c, undefined)),
    ...payments.map((p) => toPair(undefined, p)),
  ];
  return { pairs };
}

function pairImmediate(checkouts: MandateEntry[], payments: MandateEntry[]): { pairs: PairInfo[] } | { error: string } {
  const byHash = new Map<string, MandateEntry>();
  for (const c of checkouts) {
    if (c.resolved["vct"] === VI_VCT.CHECKOUT_OPEN) return { error: "Immediate mode does not allow open checkout mandates" };
    const ch = c.resolved["checkout_hash"];
    if (!ch) return { error: "Closed checkout mandate missing checkout_hash for pairing" };
    if (byHash.has(ch)) return { error: "Duplicate checkout mandates (checkout_hash collision)" };
    byHash.set(ch, c);
  }
  const byTid = new Map<string, MandateEntry>();
  for (const p of payments) {
    if (p.resolved["vct"] === VI_VCT.PAYMENT_OPEN) return { error: "Immediate mode does not allow open payment mandates" };
    const tid = p.resolved["transaction_id"];
    if (!tid) return { error: "Closed payment mandate missing transaction_id for pairing" };
    if (byTid.has(tid)) return { error: "Duplicate payment mandates (transaction_id collision)" };
    byTid.set(tid, p);
  }
  const pairs: PairInfo[] = [];
  const matched = new Set<string>();
  for (const [ch, c] of byHash) {
    const p = byTid.get(ch);
    if (!p) return { error: "Orphaned checkout mandate: no payment with matching transaction_id" };
    pairs.push(toPair(c, p));
    matched.add(ch);
  }
  for (const tid of byTid.keys()) if (!matched.has(tid)) return { error: "Orphaned payment mandate: no checkout with matching checkout_hash" };
  return { pairs };
}

function pairAutonomous(checkouts: MandateEntry[], payments: MandateEntry[]): { pairs: PairInfo[] } | { error: string } {
  const byRef = new Map<string, MandateEntry>();
  for (const c of checkouts) {
    if (!c.refHash) return { error: "Checkout mandate missing disclosure reference for pairing" };
    if (byRef.has(c.refHash)) return { error: "Duplicate checkout mandate references (pairing key collision)" };
    byRef.set(c.refHash, c);
  }
  const pairs: PairInfo[] = [];
  const matched = new Set<string>();
  for (const p of payments) {
    const constraints = (p.resolved["constraints"] ?? []) as Dict[];
    const ref = constraints.find((c) => c?.["type"] === "mandate.payment.reference");
    if (!ref) return { error: "Open payment mandate missing mandate.payment.reference constraint for pairing" };
    const cond = ref["conditional_transaction_id"];
    if (!cond) return { error: "mandate.payment.reference missing conditional_transaction_id for pairing" };
    if (matched.has(cond)) return { error: "Duplicate payment mandates referencing the same checkout" };
    const c = byRef.get(cond);
    if (!c) return { error: "Orphaned payment mandate: conditional_transaction_id matches no checkout disclosure" };
    pairs.push(toPair(c, p));
    matched.add(cond);
  }
  for (const ref of byRef.keys()) if (!matched.has(ref)) return { error: "Orphaned checkout mandate: no payment references it" };
  return { pairs };
}

function toPair(c: MandateEntry | undefined, p: MandateEntry | undefined): PairInfo {
  return {
    checkout: c?.resolved,
    payment: p?.resolved,
    checkoutDiscB64: c?.discB64,
    paymentDiscB64: p?.discB64,
  };
}

function extractAgentKey(pairs: PairInfo[]): { jwk?: Jwk; kid?: string; error?: string } {
  const jwks: Jwk[] = [];
  const kids: (string | undefined)[] = [];
  for (const pr of pairs) {
    for (const [label, m, expVct] of [
      ["checkout", pr.checkout, VI_VCT.CHECKOUT_OPEN],
      ["payment", pr.payment, VI_VCT.PAYMENT_OPEN],
    ] as const) {
      if (!m || m["vct"] !== expVct) continue;
      const jwk = m["cnf"]?.jwk;
      if (!jwk || typeof jwk !== "object") return { error: `L2 ${label} open mandate missing cnf.jwk for agent delegation` };
      jwks.push(jwk);
      kids.push(jwk.kid);
    }
  }
  if (!jwks.length) return {};
  const first = jwks[0]!;
  for (const o of jwks.slice(1)) if (o.x !== first.x || o.y !== first.y) return { error: "L2 mandate cnf.jwk values differ across pairs" };
  const nonNull = kids.filter((k): k is string => !!k);
  if (nonNull.length) {
    const fk = nonNull[0]!;
    for (const k of nonNull.slice(1)) if (k !== fk) return { error: "L2 mandate cnf.jwk.kid values differ across pairs" };
    return { jwk: first, kid: fk };
  }
  return { jwk: first };
}

function normalizeSplits(params: VerifyChainParams, pairCount: number): { list: SplitL3[] } | { error: string } {
  let list: SplitL3[];
  if (params.splitL3s) list = params.splitL3s;
  else if (params.l3Payment || params.l3Checkout)
    list = [
      {
        l3Payment: params.l3Payment,
        l3Checkout: params.l3Checkout,
        l2PaymentSerialized: params.l2PaymentSerialized,
        l2CheckoutSerialized: params.l2CheckoutSerialized,
      },
    ];
  else list = [];
  if (list.length && list.length !== pairCount)
    return { error: `Split L3 count (${list.length}) does not match mandate pair count (${pairCount})` };
  return { list };
}

/** The L3's L2 view must include this pair's mandate disclosure (binds L3 to the right pair). */
function viewBinds(viewSer: string, discB64: string | undefined, label: string): string | null {
  if (!discB64) return null; // partial disclosure — nothing to bind against
  if (!viewSer.split("~").includes(discB64)) return `${label} L2 view does not include this pair's mandate disclosure`;
  return null;
}

function cardIdCrossCheck(l1: L1, pairs: PairInfo[], ctx: Ctx): string | null {
  const cardId = l1.payload.card_id;
  if (!cardId) {
    ctx.result.checksSkipped.push("card_id_cross_check (no L1 card_id)");
    return null;
  }
  for (let i = 0; i < pairs.length; i++) {
    const pi = pairs[i]!.payment?.["payment_instrument"];
    const piId = pi?.id;
    if (!piId) return `pair ${i}: L1 card_id (${cardId}) set but payment_instrument.id missing — cannot verify binding`;
    if (piId !== cardId) return `pair ${i}: L1 card_id (${cardId}) != payment_instrument.id (${piId})`;
    ctx.result.checksPerformed.push(`pair_${i}_card_id_cross_check`);
  }
  return null;
}

function collectNetworkEnforced(pairs: PairInfo[]): NetworkEnforcedConstraint[] {
  const out: NetworkEnforcedConstraint[] = [];
  for (let i = 0; i < pairs.length; i++) {
    const constraints = (pairs[i]!.payment?.["constraints"] ?? []) as Constraint[];
    for (const c of constraints) {
      if (NETWORK_ENFORCED.has(c.type)) out.push({ pairIndex: i, type: c.type as ConstraintType, constraint: c });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Per-mandate + per-L3 checks
// ---------------------------------------------------------------------------

async function verifyMandatePair(pair: PairInfo, isAutonomous: boolean, ctx: Ctx): Promise<string | null> {
  const { checkout, payment, checkoutDiscB64 } = pair;
  if (!isAutonomous) {
    if (!checkout || !payment) return "Immediate mode requires both checkout and payment mandates";
    if ("cnf" in checkout || "cnf" in payment) return "Immediate mode mandates must not contain cnf";
    for (const field of ["checkout_jwt", "checkout_hash"]) {
      if (!checkout[field]) return `Closed checkout mandate missing required field: ${field}`;
    }
    const computed = await sha256(String(checkout["checkout_jwt"]));
    if (computed !== checkout["checkout_hash"]) return "checkout_hash != SHA-256(checkout_jwt)";
    if (payment["transaction_id"] !== checkout["checkout_hash"]) return "transaction_id != checkout_hash";
    ctx.result.checksPerformed.push("l2_checkout_payment_binding");
    return null;
  }

  if (checkout?.["vct"] === VI_VCT.CHECKOUT_OPEN) {
    const hasLineItems = (checkout["constraints"] ?? []).some((c: Dict) => c?.["type"] === "mandate.checkout.line_items");
    if (!hasLineItems) return "Open checkout mandate must contain a mandate.checkout.line_items constraint";
  }
  if (payment?.["vct"] === VI_VCT.PAYMENT_OPEN) {
    const constraints = (payment["constraints"] ?? []) as Dict[];
    if (!constraints.some((c) => c?.["type"] === "mandate.payment.reference"))
      return "Open payment mandate must contain a mandate.payment.reference constraint";
    const pi = payment["payment_instrument"];
    if (!pi || !pi.id || !pi.type) return "Open payment mandate missing payment_instrument (id + type)";
  }
  if (checkout && payment) {
    if (!checkoutDiscB64) return "L2 checkout disclosure string missing (required for reference binding)";
    const ref = ((payment["constraints"] ?? []) as Dict[]).find((c) => c?.["type"] === "mandate.payment.reference");
    const expected = ref?.["conditional_transaction_id"];
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
  l2Payment: Dict | null,
  ctx: Ctx,
  pr: PairResult,
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
    pr.l3PaymentClaims = claims;
    const err = validatePaymentMandate(claims, l2Payment, label);
    if (err) return err;
  } else {
    pr.l3CheckoutClaims = claims;
    const mandate = mandateFromClaims(claims, VI_VCT.CHECKOUT_FINAL);
    if (!mandate) return `${label} missing required checkout mandate (${VI_VCT.CHECKOUT_FINAL})`;
    for (const f of ["checkout_jwt", "checkout_hash"]) if (!mandate[f]) return `${label} checkout mandate missing ${f}`;
  }
  ctx.result.checksPerformed.push(`${label} structural_chain`);
  return null;
}

function validatePaymentMandate(claims: Record<string, unknown>, l2Payment: Dict | null, label: string): string | null {
  const m = mandateFromClaims(claims, VI_VCT.PAYMENT_FINAL);
  if (!m) return `${label} missing required payment mandate (${VI_VCT.PAYMENT_FINAL})`;
  if (!isNonEmptyStr(m["transaction_id"])) return `${label} payment mandate missing transaction_id`;
  const payee = m["payee"];
  if (!payee || typeof payee !== "object") return `${label} payment mandate payee must be an object`;
  if (!isNonEmptyStr((payee as Dict).name) || !isNonEmptyStr((payee as Dict).website))
    return `${label} payee missing name/website`;
  const pa = m["payment_amount"];
  if (!pa || typeof pa !== "object" || !isNonEmptyStr((pa as Dict).currency) || !Number.isInteger((pa as Dict).amount))
    return `${label} payment_amount missing currency/integer amount`;
  const pi = m["payment_instrument"];
  if (!pi || !isNonEmptyStr((pi as Dict).id) || !isNonEmptyStr((pi as Dict).type))
    return `${label} payment_instrument missing id/type`;
  const l2pi = l2Payment?.["payment_instrument"];
  if (l2pi && ((pi as Dict).id !== l2pi.id || (pi as Dict).type !== l2pi.type))
    return `${label} payment_instrument does not match L2 authorized value`;
  return null;
}

function mandateFromClaims(claims: Record<string, unknown>, vct: string): Dict | null {
  const delegates = Array.isArray(claims["delegate_payload"]) ? (claims["delegate_payload"] as unknown[]) : [];
  for (const d of delegates) if (d && typeof d === "object" && (d as Dict)["vct"] === vct) return d as Dict;
  return null;
}

function mandateFieldFromClaims(claims: Record<string, unknown> | undefined, vct: string, field: string): unknown {
  if (!claims) return undefined;
  return mandateFromClaims(claims, vct)?.[field];
}

function buildPaymentFulfillment(l3PaymentClaims: Record<string, unknown> | undefined, constraints: Constraint[]): Record<string, unknown> {
  const m = l3PaymentClaims ? mandateFromClaims(l3PaymentClaims, VI_VCT.PAYMENT_FINAL) : null;
  const fulfillment: Record<string, unknown> = { ...(m ?? {}) };
  const payees = (constraints as Dict[]).find((c) => c?.["type"] === "mandate.payment.allowed_payees");
  if (payees && Array.isArray(payees["allowed"])) {
    fulfillment["allowed_merchants"] = payees["allowed"].filter(
      (x: unknown) => x && typeof x === "object" && delegateRefHash(x) === null,
    );
  }
  return fulfillment;
}

function recordConstraints(result: VerificationResult, cres: ConstraintCheckResult): void {
  result.checksPerformed.push(...cres.checked.map((c) => `constraint:${c}`));
  result.checksSkipped.push(...cres.skipped.map((c) => `constraint:${c}`));
}

// ---------------------------------------------------------------------------
// Time helpers
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

function isNonEmptyStr(v: unknown): boolean {
  return typeof v === "string" && v.trim() !== "";
}
