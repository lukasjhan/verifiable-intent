/**
 * End-to-end Autonomous (3-layer) VI flow, one role at a time.
 * Run: node examples/autonomous-flow.ts   (Node 22.6+ strips the types)
 */
import {
  generateViKeyPair,
  issueL1,
  issueL2Autonomous,
  issueL3Payment,
  issueL3Checkout,
  presentL2ForNetwork,
  presentL2ForMerchant,
  verifyChain,
  baseJwtOf,
  checkoutHash,
  resolveDisclosures,
  parseLayer,
  CONSTRAINT_TYPE,
  VI_VCT,
  type Merchant,
  type Item,
  type PaymentInstrument,
} from "verifiable-intent";

const now = Math.floor(Date.now() / 1000);

// Fixtures ------------------------------------------------------------------
const MERCHANTS: Merchant[] = [{ id: "m1", name: "Tennis Warehouse", website: "https://tenniswarehouse.example" }];
const ITEMS: Item[] = [{ id: "BAB86345", sku: "BAB86345", title: "Babolat Pure Drive" }];
const PI: PaymentInstrument = { type: "card", id: "pi-1", description: "Visa ****4242" };

// 0. Keys for every principal ----------------------------------------------
const issuer = await generateViKeyPair();
const user = await generateViKeyPair();
const agent = await generateViKeyPair();

// 1. ISSUER → L1 (binds the user's key; email is selectively disclosable) ---
const l1 = await issueL1({
  iss: "https://issuer.example",
  sub: "user-alice",
  vct: VI_VCT.L1_CARD,
  userPublicJwk: user.publicJwk,
  iat: now,
  exp: now + 86_400,
  visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
  email: "alice@example.com",
  issuerPrivateKey: issuer.privateKey,
  issuerKid: issuer.kid,
});

// 2. USER → L2 (constraints + delegate to the agent key) --------------------
const l2 = await issueL2Autonomous({
  l1,
  aud: "agent://shopping-bot",
  nonce: "user-nonce-1",
  iat: now,
  exp: now + 86_400,
  userPrivateKey: user.privateKey,
  userKid: user.kid,
  agentPublicJwk: agent.publicJwk,
  agentKid: agent.kid,
  promptSummary: "Buy a Babolat tennis racket under $400",
  merchants: MERCHANTS,
  acceptableItems: ITEMS,
  checkoutConstraints: [
    { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: MERCHANTS },
    { type: CONSTRAINT_TYPE.LINE_ITEMS, match_mode: "minimum", items: [{ id: "li-1", acceptable_items: ITEMS, quantity: 1 }] },
  ],
  paymentConstraints: [
    { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 },
    { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: MERCHANTS },
  ],
  paymentInstrument: PI,
});

// 3. AGENT → picks a product, gets a merchant checkout, builds split L3 -----
const checkoutJwt = "eyJhbGciOiJFUzI1NiJ9.merchant-cart.sig"; // merchant-signed cart (opaque here)
const cHash = await checkoutHash(checkoutJwt);
const l2Base = baseJwtOf(l2.serialized);

// Selective L2 views: network sees payment+merchant, merchant sees checkout+item.
const netView = await presentL2ForNetwork(l2);
const merView = await presentL2ForMerchant(l2);

const l3a = await issueL3Payment({
  nonce: "agent-nonce-1",
  aud: "https://network.example",
  iat: now,
  exp: now + 300,
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
  nonce: "agent-nonce-1",
  aud: "https://tenniswarehouse.example",
  iat: now,
  exp: now + 300,
  agentPrivateKey: agent.privateKey,
  agentKid: agent.kid,
  l2BaseJwt: l2Base,
  checkoutJwt,
  checkoutHash: cHash,
  l2CheckoutDisclosure: merView.disclosures[0],
  l2ItemDisclosure: merView.disclosures[1],
});

// 4. NETWORK verifies the payment chain + constraints -----------------------
const resolveIssuerKey = async () => issuer.publicJwk; // real impl: fetch JWKS by iss+kid
const network = await verifyChain({ l1, l2, l3Payment: l3a, resolveIssuerKey, now, l2PaymentSerialized: netView.serialized });

// 5. MERCHANT verifies the checkout chain -----------------------------------
const merchant = await verifyChain({ l1, l2, l3Checkout: l3b, resolveIssuerKey, now, l2CheckoutSerialized: merView.serialized });

// What each party can see (privacy boundary) --------------------------------
const merchantSees = await resolveDisclosures((await parseLayer(merView.serialized)).payload, (await parseLayer(merView.serialized)).disclosureStrings);
const networkSees = await resolveDisclosures((await parseLayer(netView.serialized)).payload, (await parseLayer(netView.serialized)).disclosureStrings);

console.log("network.valid   =", network.valid, "| mode =", network.mode, "| pairs =", network.mandatePairCount);
console.log("merchant.valid  =", merchant.valid);
console.log("networkEnforced =", network.networkEnforced); // [] here: no budget/recurrence set
const vcts = (claims: Record<string, unknown>) => (claims.delegate_payload as any[]).map((d) => d?.vct).filter(Boolean);
console.log("merchant sees mandates =", vcts(merchantSees)); // only the checkout mandate
console.log("network  sees mandates =", vcts(networkSees)); // only the payment mandate

if (!network.valid || !merchant.valid) {
  console.error("FAILED", network.errors, merchant.errors);
  process.exit(1);
}
console.log("\n✅ Autonomous flow verified end-to-end.");
