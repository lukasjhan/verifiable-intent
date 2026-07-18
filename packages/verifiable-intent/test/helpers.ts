/** Shared fixtures + flow builders for the test suite. */
import {
  baseJwtOf,
  checkoutHash,
  CONSTRAINT_TYPE,
  generateViKeyPair,
  issueL1,
  issueL2Autonomous,
  issueL2Immediate,
  issueL3Checkout,
  issueL3Payment,
  presentL2ForMerchant,
  presentL2ForNetwork,
  VI_VCT,
  type Constraint,
  type Item,
  type L1,
  type L2,
  type L3Checkout,
  type L3Payment,
  type Merchant,
  type PaymentInstrument,
  type RoleView,
  type ViKeyPair,
} from "../src/index.js";

export const NOW = 1_700_000_000;
export const MERCHANTS: Merchant[] = [
  { id: "m1", name: "Tennis Warehouse", website: "https://tw.example" },
  { id: "m2", name: "Racket World", website: "https://rw.example" },
];
export const ITEMS: Item[] = [
  { id: "BAB86345", sku: "BAB86345", title: "Babolat Pure Drive" },
  { id: "WIL12000", sku: "WIL12000", title: "Wilson Blade" },
];
export const PI: PaymentInstrument = { type: "card", id: "pi-1", description: "Visa ****4242" };
export const CART_JWT = "eyJhbGciOiJFUzI1NiJ9.tennis-cart.sig";

export interface Keys {
  issuer: ViKeyPair;
  user: ViKeyPair;
  agent: ViKeyPair;
}

export async function keys(): Promise<Keys> {
  const [issuer, user, agent] = await Promise.all([generateViKeyPair(), generateViKeyPair(), generateViKeyPair()]);
  return { issuer, user, agent };
}

export function makeL1(k: Keys, overrides: Partial<Parameters<typeof issueL1>[0]> = {}): Promise<L1> {
  return issueL1({
    iss: "https://issuer.example",
    sub: "user-alice",
    vct: VI_VCT.L1_CARD,
    userPublicJwk: k.user.publicJwk,
    iat: NOW,
    exp: NOW + 86_400,
    visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
    email: "alice@example.com",
    issuerPrivateKey: k.issuer.privateKey,
    issuerKid: k.issuer.kid,
    ...overrides,
  });
}

export const CHECKOUT_CONSTRAINTS: Constraint[] = [
  { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: MERCHANTS },
  { type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-1", acceptable_items: ITEMS, quantity: 1 }] },
];
export const PAYMENT_CONSTRAINTS: Constraint[] = [
  { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 },
  { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: MERCHANTS },
];

export function autonomousL2(l1: L1, k: Keys, overrides: Partial<Parameters<typeof issueL2Autonomous>[0]> = {}): Promise<L2> {
  return issueL2Autonomous({
    l1,
    aud: "agent://bot",
    nonce: "n1",
    iat: NOW,
    exp: NOW + 86_400,
    userPrivateKey: k.user.privateKey,
    userKid: k.user.kid,
    agentPublicJwk: k.agent.publicJwk,
    agentKid: k.agent.kid,
    merchants: MERCHANTS,
    acceptableItems: ITEMS,
    checkoutConstraints: CHECKOUT_CONSTRAINTS,
    paymentConstraints: PAYMENT_CONSTRAINTS,
    paymentInstrument: PI,
    ...overrides,
  });
}

export interface AutonomousFlow {
  k: Keys;
  l1: L1;
  l2: L2;
  l3a: L3Payment;
  l3b: L3Checkout;
  netView: RoleView;
  merView: RoleView;
  resolveIssuerKey: () => Promise<import("../src/index.js").Jwk>;
}

/** A complete, valid Autonomous single-pair flow. Tests mutate one piece to exercise negatives. */
export async function autonomousFlow(
  opts: { amount?: number; l3aOverride?: Partial<Parameters<typeof issueL3Payment>[0]>; l3bOverride?: Partial<Parameters<typeof issueL3Checkout>[0]> } = {},
): Promise<AutonomousFlow> {
  const k = await keys();
  const l1 = await makeL1(k);
  const l2 = await autonomousL2(l1, k);
  const cHash = await checkoutHash(CART_JWT);
  const l2Base = baseJwtOf(l2.serialized);
  const netView = await presentL2ForNetwork(l2);
  const merView = await presentL2ForMerchant(l2);

  const l3a = await issueL3Payment({
    nonce: "l3n",
    aud: "https://network.example",
    iat: NOW,
    exp: NOW + 300,
    agentPrivateKey: k.agent.privateKey,
    agentKid: k.agent.kid,
    l2BaseJwt: l2Base,
    transactionId: cHash,
    payee: MERCHANTS[0]!,
    paymentAmount: { currency: "USD", amount: opts.amount ?? 25000 },
    paymentInstrument: PI,
    finalMerchant: MERCHANTS[0]!,
    l2PaymentDisclosure: netView.disclosures[0],
    l2MerchantDisclosure: netView.disclosures[1],
    ...opts.l3aOverride,
  });

  const l3b = await issueL3Checkout({
    nonce: "l3n",
    aud: "https://tw.example",
    iat: NOW,
    exp: NOW + 300,
    agentPrivateKey: k.agent.privateKey,
    agentKid: k.agent.kid,
    l2BaseJwt: l2Base,
    checkoutJwt: CART_JWT,
    checkoutHash: cHash,
    l2CheckoutDisclosure: merView.disclosures[0],
    l2ItemDisclosure: merView.disclosures[1],
    ...opts.l3bOverride,
  });

  return { k, l1, l2, l3a, l3b, netView, merView, resolveIssuerKey: async () => k.issuer.publicJwk };
}

export function immediateL2(l1: L1, k: Keys, overrides: Partial<Parameters<typeof issueL2Immediate>[0]> = {}): Promise<L2> {
  return issueL2Immediate({
    l1,
    aud: "agent://bot",
    nonce: "n1",
    iat: NOW,
    exp: NOW + 900,
    userPrivateKey: k.user.privateKey,
    userKid: k.user.kid,
    checkoutJwt: CART_JWT,
    payee: MERCHANTS[0]!,
    paymentAmount: { currency: "USD", amount: 4200 },
    paymentInstrument: PI,
    ...overrides,
  });
}
