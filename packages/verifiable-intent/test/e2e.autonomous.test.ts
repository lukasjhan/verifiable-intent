import { describe, it, expect } from "vitest";
import {
  baseJwtOf,
  checkoutHash,
  generateViKeyPair,
  issueL3Payment,
  parseLayer,
  signSdJwt,
  verifyChain,
} from "../src/index.js";
import { autonomousFlow, CART_JWT, MERCHANTS, NOW, PI } from "./helpers.js";

describe("Autonomous flow — happy path", () => {
  it("network verifies the payment chain + constraints", async () => {
    const f = await autonomousFlow();
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: f.l3a, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.netView.serialized });
    expect(r.errors).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.mode).toBe("AUTONOMOUS");
    expect(r.mandatePairCount).toBe(1);
    expect(r.networkEnforced).toEqual([]); // default constraints have no budget/recurrence
  });

  it("merchant verifies the checkout chain", async () => {
    const f = await autonomousFlow();
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Checkout: f.l3b, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2CheckoutSerialized: f.merView.serialized });
    expect(r.errors).toEqual([]);
    expect(r.valid).toBe(true);
  });

  it("full chain (both legs) passes the cross-reference", async () => {
    const f = await autonomousFlow();
    const r = await verifyChain({
      l1: f.l1, l2: f.l2, l3Payment: f.l3a, l3Checkout: f.l3b, resolveIssuerKey: f.resolveIssuerKey, now: NOW,
      l2PaymentSerialized: f.netView.serialized, l2CheckoutSerialized: f.merView.serialized,
    });
    expect(r.errors).toEqual([]);
    expect(r.checksPerformed).toContain("pair_0_l3_cross_reference");
  });
});

describe("Autonomous flow — constraint negatives", () => {
  it("rejects an amount above the range", async () => {
    const f = await autonomousFlow({ amount: 99999 });
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: f.l3a, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.netView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/exceeds maximum/);
  });

  it("rejects a payee outside the allowlist", async () => {
    const f = await autonomousFlow({ l3aOverride: { payee: { id: "m9", name: "Evil Corp", website: "https://evil.example" } } });
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: f.l3a, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.netView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/not in allowed/);
  });
});

describe("Autonomous flow — L3 structural negatives", () => {
  it("rejects an L3 header kid that does not match the L2 cnf kid", async () => {
    const f = await autonomousFlow({ l3aOverride: { agentKid: "wrong-kid" } });
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: f.l3a, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.netView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/kid/);
  });

  it("rejects an L3 sd_hash bound to the wrong L2 view", async () => {
    const f = await autonomousFlow();
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: f.l3a, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.merView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/sd_hash|does not include/);
  });

  it("rejects an expired L3", async () => {
    const f = await autonomousFlow();
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: f.l3a, resolveIssuerKey: f.resolveIssuerKey, now: NOW + 1000, l2PaymentSerialized: f.netView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/expired/);
  });

  it("rejects an L3 whose lifetime exceeds 1 hour", async () => {
    const f = await autonomousFlow({ l3aOverride: { exp: NOW + 4000 } });
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: f.l3a, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.netView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/1 hour/);
  });

  it("rejects an L3 cross-reference mismatch", async () => {
    const f = await autonomousFlow({ l3bOverride: { checkoutHash: "deadbeef" } });
    const r = await verifyChain({
      l1: f.l1, l2: f.l2, l3Payment: f.l3a, l3Checkout: f.l3b, resolveIssuerKey: f.resolveIssuerKey, now: NOW,
      l2PaymentSerialized: f.netView.serialized, l2CheckoutSerialized: f.merView.serialized,
    });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/cross-reference/);
  });

  it("rejects an L3 signed by a key other than the delegated agent key", async () => {
    const f = await autonomousFlow();
    const impostor = await generateViKeyPair();
    const cHash = await checkoutHash(CART_JWT);
    // Same kid as the real agent, but signed by the impostor → signature must fail.
    const forged = await issueL3Payment({
      nonce: "l3n", aud: "https://network.example", iat: NOW, exp: NOW + 300,
      agentPrivateKey: impostor.privateKey, agentKid: f.k.agent.kid, l2BaseJwt: baseJwtOf(f.l2.serialized),
      transactionId: cHash, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: 25000 },
      paymentInstrument: PI, finalMerchant: MERCHANTS[0]!,
      l2PaymentDisclosure: f.netView.disclosures[0], l2MerchantDisclosure: f.netView.disclosures[1],
    });
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: forged, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.netView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/agent key mismatch/);
  });

  it("rejects an L3 that carries a cnf (non-terminal delegation)", async () => {
    const f = await autonomousFlow();
    // Hand-craft an L3a payload with an illegal cnf, signed by the real agent key.
    const good = await parseLayer(f.l3a.serialized);
    const payload = { ...good.payload, cnf: { jwk: f.k.agent.publicJwk } };
    const encoded = await signSdJwt(
      { alg: "ES256", typ: "kb-sd-jwt", kid: f.k.agent.kid },
      payload,
      good.disclosureStrings,
      f.k.agent.privateKey,
    );
    const l3WithCnf = await parseLayer<any>(encoded);
    const r = await verifyChain({ l1: f.l1, l2: f.l2, l3Payment: l3WithCnf, resolveIssuerKey: f.resolveIssuerKey, now: NOW, l2PaymentSerialized: f.netView.serialized });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/MUST NOT contain cnf/);
  });
});
