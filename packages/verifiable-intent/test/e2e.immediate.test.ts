import { describe, it, expect } from "vitest";
import { generateViKeyPair, verifyChain } from "../src/index.js";
import { keys, makeL1, immediateL2, NOW } from "./helpers.js";

describe("Immediate flow — happy path", () => {
  it("issues L1 → L2 and verifies", async () => {
    const k = await keys();
    const l1 = await makeL1(k);
    const l2 = await immediateL2(l1, k);
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.errors).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.mode).toBe("IMMEDIATE");
    expect(r.mandatePairCount).toBe(1);
    expect(r.checksPerformed).toContain("l2_checkout_payment_binding");
    expect(r.checksPerformed).toContain("pair_0_card_id_cross_check");
  });
});

describe("Immediate flow — negatives", () => {
  async function base() {
    const k = await keys();
    return { k, l1: await makeL1(k) };
  }

  it("rejects a wrong checkout_hash", async () => {
    const { k, l1 } = await base();
    const l2 = await immediateL2(l1, k, { checkoutHash: "not-the-real-hash" });
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/checkout_hash/);
  });

  it("rejects transaction_id != checkout_hash", async () => {
    const { k, l1 } = await base();
    const l2 = await immediateL2(l1, k, { transactionId: "mismatched" });
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/transaction_id/);
  });

  it("rejects a wrong issuer key (L1 signature)", async () => {
    const { k, l1 } = await base();
    const l2 = await immediateL2(l1, k);
    const wrong = await generateViKeyPair();
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => wrong.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/L1 signature/);
  });

  it("rejects an expired credential", async () => {
    const { k, l1 } = await base();
    const l2 = await immediateL2(l1, k);
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW + 200_000 });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/expired/);
  });

  it("rejects a card_id / payment_instrument mismatch", async () => {
    const k = await keys();
    const l1 = await makeL1(k, { visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-999" } });
    const l2 = await immediateL2(l1, k); // payment_instrument.id = pi-1
    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/card_id/);
  });

  it("rejects L3 supplied for an immediate L2", async () => {
    const { k, l1 } = await base();
    const l2 = await immediateL2(l1, k);
    const fakeL3 = (await immediateL2(l1, k)) as any; // any layer object; presence alone must be rejected
    const r = await verifyChain({ l1, l2, l3Payment: fakeL3, resolveIssuerKey: async () => k.issuer.publicJwk, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/immediate-mode/);
  });
});
