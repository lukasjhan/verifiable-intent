/**
 * Immediate (2-layer) VI flow: the user signs the FINAL cart + payment values; the agent only
 * forwards them (no L3, no constraints).
 * Run: node examples/immediate-flow.ts
 */
import {
  generateViKeyPair,
  issueL1,
  issueL2Immediate,
  verifyChain,
  VI_VCT,
  type Merchant,
  type PaymentInstrument,
} from "verifiable-intent";

const now = Math.floor(Date.now() / 1000);
const merchant: Merchant = { id: "m1", name: "Tennis Warehouse", website: "https://tenniswarehouse.example" };
const PI: PaymentInstrument = { type: "card", id: "pi-1" };

const issuer = await generateViKeyPair();
const user = await generateViKeyPair();

// L1 — issuer binds the user's key.
const l1 = await issueL1({
  iss: "https://issuer.example",
  vct: VI_VCT.L1_CARD,
  userPublicJwk: user.publicJwk,
  iat: now,
  exp: now + 86_400,
  visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
  email: "alice@example.com",
  issuerPrivateKey: issuer.privateKey,
  issuerKid: issuer.kid,
});

// L2 — user confirms the final cart + payment. checkout_hash / transaction_id are auto-derived
// from `checkoutJwt` and cross-linked.
const l2 = await issueL2Immediate({
  l1,
  aud: "agent://shopping-bot",
  nonce: "user-nonce-1",
  iat: now,
  exp: now + 900,
  userPrivateKey: user.privateKey,
  userKid: user.kid,
  checkoutJwt: "eyJhbGciOiJFUzI1NiJ9.final-cart.sig",
  payee: merchant,
  paymentAmount: { currency: "USD", amount: 4200 },
  paymentInstrument: PI,
});

// Verify (no L3 in Immediate mode).
const result = await verifyChain({ l1, l2, resolveIssuerKey: async () => issuer.publicJwk, now });

console.log("valid =", result.valid, "| mode =", result.mode);
console.log("checks =", result.checksPerformed);
if (!result.valid) {
  console.error("FAILED", result.errors);
  process.exit(1);
}
console.log("\n✅ Immediate flow verified.");
