import { describe, it, expect } from "vitest";
import {
  baseJwtOf,
  checkoutHash,
  CONSTRAINT_TYPE,
  createDisclosure,
  generateViKeyPair,
  hashDisclosure,
  issueL1,
  issueL2Autonomous,
  issueL2Immediate,
  issueL3Checkout,
  issueL3Payment,
  presentL2ForMerchant,
  presentL2ForNetwork,
  resolveDisclosures,
  sdHash,
  VI_VCT,
  verifyChain,
  type Jwk,
  type L1,
  type Merchant,
  type Item,
  type PaymentInstrument,
  type ViKeyPair,
} from "../src/index.js";

const NOW = 1_700_000_000;

const MERCHANTS: Merchant[] = [{ id: "m1", name: "Tennis Warehouse", website: "https://tw.example" }];
const ITEMS: Item[] = [{ id: "BAB86345", sku: "BAB86345", title: "Babolat Pure Drive" }];
const PI: PaymentInstrument = { type: "card", id: "pi-1", description: "Visa ****4242" };

async function makeL1() {
  const issuer = await generateViKeyPair();
  const user = await generateViKeyPair();
  const l1 = await issueL1({
    iss: "https://issuer.example",
    sub: "user-1",
    vct: VI_VCT.L1_CARD,
    userPublicJwk: user.publicJwk,
    iat: NOW,
    exp: NOW + 86_400,
    visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
    email: "alice@example.com",
    issuerPrivateKey: issuer.privateKey,
    issuerKid: issuer.kid,
  });
  return { issuer, user, l1 };
}

describe("disclosure core (via @sd-jwt/core)", () => {
  it("createDisclosure + hashDisclosure are stable and base64url", async () => {
    const d = createDisclosure("email", "a@b.com", "fixed-salt");
    expect(d).toMatch(/^[A-Za-z0-9_-]+$/);
    const h = await hashDisclosure(d);
    expect(h).toBe(await hashDisclosure(d));
  });

  it("L1 email is packed by the library and resolves back", async () => {
    const { l1 } = await makeL1();
    expect(l1.payload._sd).toBeInstanceOf(Array); // library packed `email` into _sd
    const claims = await resolveDisclosures(l1.payload, l1.disclosureStrings);
    expect(claims["email"]).toBe("alice@example.com");
  });
});

describe("Immediate flow (L1 → L2)", () => {
  it("issues and verifies", async () => {
    const { issuer, user, l1 } = await makeL1();
    const cartJwt = "eyJhbGciOiJFUzI1NiJ9.cart.sig";

    const l2 = await issueL2Immediate({
      l1,
      aud: "agent://bot",
      nonce: "n1",
      iat: NOW,
      exp: NOW + 900,
      userPrivateKey: user.privateKey,
      userKid: user.kid,
      checkoutJwt: cartJwt,
      payee: MERCHANTS[0]!,
      paymentAmount: { currency: "USD", amount: 4200 },
      paymentInstrument: PI,
    });

    expect(l2.payload.sd_hash).toBe(await sdHash(l1.serialized));

    const r = await verifyChain({ l1, l2, resolveIssuerKey: async () => issuer.publicJwk, now: NOW });
    expect(r.errors).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.mode).toBe("IMMEDIATE");
    expect(r.checksPerformed).toContain("l2_checkout_payment_binding");
  });
});

describe("Autonomous flow (L1 → L2 → L3a/L3b) with selective disclosure", () => {
  async function autonomousL2(l1: L1, user: ViKeyPair, agentKid: string, agentJwk: Jwk) {
    return issueL2Autonomous({
      l1,
      aud: "agent://bot",
      nonce: "n1",
      iat: NOW,
      exp: NOW + 86_400,
      userPrivateKey: user.privateKey,
      userKid: user.kid,
      agentPublicJwk: agentJwk,
      agentKid,
      promptSummary: "Buy a tennis racket under $400",
      merchants: MERCHANTS,
      acceptableItems: ITEMS,
      checkoutConstraints: [
        { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: MERCHANTS },
        { type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-1", acceptable_items: ITEMS, quantity: 1 }] },
      ],
      paymentConstraints: [
        { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 },
        { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: MERCHANTS },
      ],
      paymentInstrument: PI,
    });
  }

  it("issues, routes selectively, and verifies both legs + cross-reference", async () => {
    const { issuer, user, l1 } = await makeL1();
    const agent = await generateViKeyPair();
    const l2 = await autonomousL2(l1, user, agent.kid, agent.publicJwk);

    expect(l2.disclosures).toHaveLength(4); // merchant + item + checkout + payment
    expect(l2.header.typ).toBe("kb-sd-jwt+kb");

    const cartJwt = "eyJhbGciOiJFUzI1NiJ9.tennis-cart.sig";
    const cHash = await checkoutHash(cartJwt);
    const l2Base = baseJwtOf(l2.serialized);
    const netView = await presentL2ForNetwork(l2);
    const merView = await presentL2ForMerchant(l2);

    const l3a = await issueL3Payment({
      nonce: "l3n",
      aud: "https://network.example",
      iat: NOW,
      exp: NOW + 300,
      agentPrivateKey: agent.privateKey,
      agentKid: agent.kid,
      l2BaseJwt: l2Base,
      transactionId: cHash,
      payee: MERCHANTS[0]!,
      paymentAmount: { currency: "USD", amount: 25000 },
      paymentInstrument: PI,
      finalMerchant: MERCHANTS[0]!,
      l2PaymentDisclosure: netView.disclosures[0],
      l2MerchantDisclosure: netView.disclosures[1],
    });

    const l3b = await issueL3Checkout({
      nonce: "l3n",
      aud: "https://tw.example",
      iat: NOW,
      exp: NOW + 300,
      agentPrivateKey: agent.privateKey,
      agentKid: agent.kid,
      l2BaseJwt: l2Base,
      checkoutJwt: cartJwt,
      checkoutHash: cHash,
      l2CheckoutDisclosure: merView.disclosures[0],
      l2ItemDisclosure: merView.disclosures[1],
    });

    const resolveIssuerKey = async () => issuer.publicJwk;
    const net = await verifyChain({ l1, l2, l3Payment: l3a, resolveIssuerKey, now: NOW, l2PaymentSerialized: netView.serialized });
    expect(net.errors).toEqual([]);
    expect(net.valid).toBe(true);
    expect(net.mode).toBe("AUTONOMOUS");

    const mer = await verifyChain({ l1, l2, l3Checkout: l3b, resolveIssuerKey, now: NOW, l2CheckoutSerialized: merView.serialized });
    expect(mer.errors).toEqual([]);
    expect(mer.valid).toBe(true);

    const full = await verifyChain({ l1, l2, l3Payment: l3a, l3Checkout: l3b, resolveIssuerKey, now: NOW, l2PaymentSerialized: netView.serialized, l2CheckoutSerialized: merView.serialized });
    expect(full.errors).toEqual([]);
    expect(full.checksPerformed).toContain("l3_cross_reference");
  });

  it("rejects an amount outside the constraint range", async () => {
    const { issuer, user, l1 } = await makeL1();
    const agent = await generateViKeyPair();
    const l2 = await autonomousL2(l1, user, agent.kid, agent.publicJwk);

    const cartJwt = "eyJhbGciOiJFUzI1NiJ9.expensive.sig";
    const cHash = await checkoutHash(cartJwt);
    const netView = await presentL2ForNetwork(l2);
    const l3a = await issueL3Payment({
      nonce: "l3n",
      aud: "https://network.example",
      iat: NOW,
      exp: NOW + 300,
      agentPrivateKey: agent.privateKey,
      agentKid: agent.kid,
      l2BaseJwt: baseJwtOf(l2.serialized),
      transactionId: cHash,
      payee: MERCHANTS[0]!,
      paymentAmount: { currency: "USD", amount: 99999 },
      paymentInstrument: PI,
      finalMerchant: MERCHANTS[0]!,
      l2PaymentDisclosure: netView.disclosures[0],
      l2MerchantDisclosure: netView.disclosures[1],
    });
    const net = await verifyChain({ l1, l2, l3Payment: l3a, resolveIssuerKey: async () => issuer.publicJwk, now: NOW, l2PaymentSerialized: netView.serialized });
    expect(net.valid).toBe(false);
    expect(net.errors.join(" ")).toMatch(/exceeds maximum/);
  });
});
