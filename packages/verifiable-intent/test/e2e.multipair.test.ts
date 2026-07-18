import { describe, it, expect } from "vitest";
import {
  baseJwtOf,
  checkoutHash,
  createDelegateRef,
  createDisclosure,
  encodePresentation,
  findDisclosures,
  hashDisclosure,
  issueL2AutonomousMultiPair,
  issueL3Checkout,
  issueL3Payment,
  parseLayer,
  sha256,
  signSdJwt,
  CONSTRAINT_TYPE,
  VI_VCT,
  type SplitL3,
  type L2,
} from "../src/index.js";
import {
  CHECKOUT_CONSTRAINTS,
  ITEMS,
  keys,
  makeL1,
  MERCHANTS,
  NOW,
  PAYMENT_CONSTRAINTS,
  PI,
  autonomousL2,
  type Keys,
} from "./helpers.js";
import { verifyChain } from "../src/index.js";

const isVct = (vct: string) => (v: unknown) => (v as any)?.vct === vct;

/** Build a valid split L3 (L3a + L3b) for every mandate pair in a multi-pair L2. */
async function buildSplits(l2: L2, k: Keys, pairCount: number): Promise<SplitL3[]> {
  const l2Base = baseJwtOf(l2.serialized);
  const payments = findDisclosures(l2, isVct(VI_VCT.PAYMENT_OPEN));
  const checkouts = findDisclosures(l2, isVct(VI_VCT.CHECKOUT_OPEN));
  const merchant = findDisclosures(l2, (v) => (v as any)?.website && !(v as any)?.vct)[0]!;
  const item = findDisclosures(l2, (v) => (v as any)?.sku && !(v as any)?.vct)[0]!;

  const splits: SplitL3[] = [];
  for (let i = 0; i < pairCount; i++) {
    const cart = `eyJhbGciOiJFUzI1NiJ9.cart-${i}.sig`;
    const cHash = await checkoutHash(cart);
    const netView = await encodePresentation(l2Base, [payments[i]!.encoded, merchant.encoded]);
    const merView = await encodePresentation(l2Base, [checkouts[i]!.encoded, item.encoded]);
    const l3Payment = await issueL3Payment({
      nonce: `n${i}`, aud: "https://network.example", iat: NOW, exp: NOW + 300,
      agentPrivateKey: k.agent.privateKey, agentKid: k.agent.kid, l2BaseJwt: l2Base,
      transactionId: cHash, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: 20000 },
      paymentInstrument: PI, finalMerchant: MERCHANTS[0]!,
      l2PaymentDisclosure: payments[i]!.encoded, l2MerchantDisclosure: merchant.encoded,
    });
    const l3Checkout = await issueL3Checkout({
      nonce: `n${i}`, aud: "https://tw.example", iat: NOW, exp: NOW + 300,
      agentPrivateKey: k.agent.privateKey, agentKid: k.agent.kid, l2BaseJwt: l2Base,
      checkoutJwt: cart, checkoutHash: cHash,
      l2CheckoutDisclosure: checkouts[i]!.encoded, l2ItemDisclosure: item.encoded,
    });
    splits.push({ l3Payment, l3Checkout, l2PaymentSerialized: netView, l2CheckoutSerialized: merView });
  }
  return splits;
}

async function twoPairL2(k: Keys) {
  const l1 = await makeL1(k);
  const pair = { checkoutConstraints: CHECKOUT_CONSTRAINTS, paymentConstraints: PAYMENT_CONSTRAINTS, paymentInstrument: PI };
  const l2 = await issueL2AutonomousMultiPair({
    l1, aud: "agent://bot", nonce: "n1", iat: NOW, exp: NOW + 86_400,
    userPrivateKey: k.user.privateKey, userKid: k.user.kid,
    agentPublicJwk: k.agent.publicJwk, agentKid: k.agent.kid,
    merchants: MERCHANTS, acceptableItems: ITEMS, pairs: [pair, pair],
  });
  return { l1, l2 };
}

describe("Multi-pair Autonomous — happy path", () => {
  it("verifies two independent mandate pairs with per-pair cross-references", async () => {
    const k = await keys();
    const { l1, l2 } = await twoPairL2(k);
    expect(findDisclosures(l2, isVct(VI_VCT.PAYMENT_OPEN))).toHaveLength(2);

    const splitL3s = await buildSplits(l2, k, 2);
    const r = await verifyChain({ l1, l2, splitL3s, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.errors).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.mandatePairCount).toBe(2);
    expect(r.checksPerformed).toContain("pair_0_l3_cross_reference");
    expect(r.checksPerformed).toContain("pair_1_l3_cross_reference");
  });

  it("rejects a split-L3 count that does not match the pair count", async () => {
    const k = await keys();
    const { l1, l2 } = await twoPairL2(k);
    const splitL3s = await buildSplits(l2, k, 2);
    const r = await verifyChain({ l1, l2, splitL3s: [splitL3s[0]!], resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/Split L3 count/);
  });
});

// ---------------------------------------------------------------------------
// Hand-crafted malformed L2 (signed by the real user key) — pairing hardening.
// ---------------------------------------------------------------------------

async function craftL2(k: Keys, l1: Awaited<ReturnType<typeof makeL1>>, delegateHashes: string[], disclosures: string[]): Promise<L2> {
  const payload = {
    nonce: "n", aud: "agent://bot", iat: NOW, exp: NOW + 86_400,
    sd_hash: await sha256(l1.serialized),
    delegate_payload: delegateHashes.map((h) => createDelegateRef(h)),
    _sd_alg: "sha-256",
  };
  const encoded = await signSdJwt({ alg: "ES256", typ: "kb-sd-jwt+kb", kid: k.user.kid }, payload, disclosures, k.user.privateKey);
  return parseLayer<any>(encoded);
}

function openMandates(k: Keys, condTxId: string) {
  const cnf = { jwk: { ...k.agent.publicJwk, kid: k.agent.kid } };
  const checkoutDict = { vct: VI_VCT.CHECKOUT_OPEN, cnf, constraints: [{ type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-1", acceptable_items: [], quantity: 1 }] }] };
  const paymentDict = { vct: VI_VCT.PAYMENT_OPEN, cnf, payment_instrument: PI, constraints: [{ type: CONSTRAINT_TYPE.REFERENCE, conditional_transaction_id: condTxId }] };
  return { checkoutDisc: createDisclosure(null, checkoutDict), paymentDict };
}

describe("Multi-pair Autonomous — pairing hardening", () => {
  it("rejects duplicate delegate references (mandate smuggling)", async () => {
    const k = await keys();
    const l1 = await makeL1(k);
    const cnf = { jwk: { ...k.agent.publicJwk, kid: k.agent.kid } };
    const checkoutDisc = createDisclosure(null, { vct: VI_VCT.CHECKOUT_OPEN, cnf, constraints: [{ type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-1", acceptable_items: [], quantity: 1 }] }] });
    const cHash = await hashDisclosure(checkoutDisc);
    const paymentDisc = createDisclosure(null, { vct: VI_VCT.PAYMENT_OPEN, cnf, payment_instrument: PI, constraints: [{ type: CONSTRAINT_TYPE.REFERENCE, conditional_transaction_id: cHash }] });
    const pHash = await hashDisclosure(paymentDisc);
    // delegate_payload references the payment mandate TWICE.
    const l2 = await craftL2(k, l1, [cHash, pHash, pHash], [checkoutDisc, paymentDisc]);
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/mandate smuggling|duplicate disclosure reference/);
  });

  it("rejects an orphaned payment mandate (reference points nowhere)", async () => {
    const k = await keys();
    const l1 = await makeL1(k);
    const { checkoutDisc, paymentDict } = openMandates(k, "points-to-no-checkout");
    const cHash = await hashDisclosure(checkoutDisc);
    const paymentDisc = createDisclosure(null, paymentDict);
    const pHash = await hashDisclosure(paymentDisc);
    const l2 = await craftL2(k, l1, [cHash, pHash], [checkoutDisc, paymentDisc]);
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/Orphaned/);
  });
});

// ---------------------------------------------------------------------------
// Network-enforced constraints are surfaced, not silently passed.
// ---------------------------------------------------------------------------

describe("Network-enforced constraints", () => {
  it("surfaces budget in the result for the caller to enforce (valid stays true)", async () => {
    const k = await keys();
    const l1 = await makeL1(k);
    const l2 = await autonomousL2(l1, k, {
      paymentConstraints: [
        ...PAYMENT_CONSTRAINTS,
        { type: CONSTRAINT_TYPE.BUDGET, currency: "USD", max: 100000 },
      ],
    });
    const splitL3s = await buildSplits(l2, k, 1);
    const r = await verifyChain({ l1, l2, splitL3s, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(true);
    expect(r.networkEnforced?.map((n) => n.type)).toContain(CONSTRAINT_TYPE.BUDGET);
  });
});
