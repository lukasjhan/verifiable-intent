import {
  baseJwtOf,
  checkoutHash,
  CONSTRAINT_TYPE,
  encodePresentation,
  findDisclosures,
  generateViKeyPair,
  issueL1,
  issueL2Autonomous,
  issueL2AutonomousMultiPair,
  issueL2Immediate,
  issueL3Checkout,
  issueL3Payment,
  parseLayer,
  presentL2ForMerchant,
  presentL2ForNetwork,
  resolveDisclosures,
  VI_VCT,
  verifyChain,
  type Constraint,
  type Item,
  type L3Checkout,
  type L3Payment,
  type Merchant,
  type PaymentInstrument,
  type RoleView,
  type SplitL3,
  type VerificationResult,
  type ViKeyPair,
  type ViLayer,
} from "verifiable-intent";

export type Actor = "issuer" | "user" | "agent" | "merchant" | "network";

const MERCHANTS: Merchant[] = [{ id: "m1", name: "Tennis Warehouse", website: "https://tenniswarehouse.example" }];
const ITEMS: Item[] = [{ id: "BAB86345", sku: "BAB86345", title: "Babolat Pure Drive" }];
const PI: PaymentInstrument = { type: "card", id: "pi-1", description: "Visa ****4242" };
const CART_JWT = "eyJhbGciOiJFUzI1NiJ9.merchant-signed-cart.sig";

export interface Built {
  mode: "IMMEDIATE" | "AUTONOMOUS";
  kids: { issuer: string; user: string; agent?: string };
  l1: ViLayer;
  l2: ViLayer;
  l3a?: ViLayer;
  l3b?: ViLayer;
  networkView?: RoleView;
  merchantView?: RoleView;
  /** Resolved mandate `vct`s each party can see after selective disclosure. */
  merchantSees?: string[];
  networkSees?: string[];
  networkResult?: VerificationResult;
  merchantResult?: VerificationResult;
  /** Human-readable values for the annotated (non-raw) explanations. */
  payment?: { amount: string; payee: string; txId: string };
  limits?: { cap: string; merchant: string; item: string };
  pairCount?: number;
  networkEnforced?: string[];
}

export interface StepMeta {
  id: "setup" | "l1" | "l2" | "l3" | "route" | "verify";
  actor: Actor | "system";
  title: string;
  /** Plain-language explanation of what happens and who receives what. */
  situation: string;
  transfer?: { from: Actor; to: Actor; what: string };
  /** Extra actors to highlight (beyond `actor` / `transfer.to`). */
  active?: Actor[];
}

export interface ScenarioDef {
  id: string;
  icon: string;
  title: string;
  tagline: string;
  outcome: "success" | "blocked";
  facts: { label: string; value: string }[];
  steps: StepMeta[];
  build: () => Promise<Built>;
}

const now = () => Math.floor(Date.now() / 1000);

async function mandateVcts(view: RoleView): Promise<string[]> {
  const l = await parseLayer(view.serialized);
  const claims = await resolveDisclosures(l.payload, l.disclosureStrings);
  const dels = Array.isArray(claims["delegate_payload"]) ? (claims["delegate_payload"] as any[]) : [];
  return dels.map((d) => d?.vct).filter(Boolean);
}

async function issuerAndUser() {
  const issuer = await generateViKeyPair();
  const user = await generateViKeyPair();
  const t = now();
  const l1 = await issueL1({
    iss: "https://bank.example",
    sub: "user-alice",
    vct: VI_VCT.L1_CARD,
    userPublicJwk: user.publicJwk,
    iat: t,
    exp: t + 86_400,
    visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
    email: "alice@example.com",
    issuerPrivateKey: issuer.privateKey,
    issuerKid: issuer.kid,
  });
  return { issuer, user, t, l1 };
}

/** Shared Autonomous setup: L1 + L2 (with a ≤$400 cap) + the two selective L2 views. */
async function autonomousBase() {
  const { issuer, user, t, l1 } = await issuerAndUser();
  const agent = await generateViKeyPair();
  const l2 = await issueL2Autonomous({
    l1,
    aud: "agent://alice-shopping-bot",
    nonce: crypto.randomUUID(),
    iat: t,
    exp: t + 86_400,
    userPrivateKey: user.privateKey,
    userKid: user.kid,
    agentPublicJwk: agent.publicJwk,
    agentKid: agent.kid,
    promptSummary: "Buy a Babolat tennis racket under $400 from an approved store",
    merchants: MERCHANTS,
    acceptableItems: ITEMS,
    checkoutConstraints: [
      { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: MERCHANTS },
      { type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-1", acceptable_items: ITEMS, quantity: 1 }] },
    ],
    paymentConstraints: [
      { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 }, // max $400.00
      { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: MERCHANTS },
    ],
    paymentInstrument: PI,
  });
  const cHash = await checkoutHash(CART_JWT);
  const l2Base = baseJwtOf(l2.serialized);
  const networkView = await presentL2ForNetwork(l2);
  const merchantView = await presentL2ForMerchant(l2);
  return { issuer, user, agent, t, l1, l2, cHash, l2Base, networkView, merchantView };
}

type AutoBase = Awaited<ReturnType<typeof autonomousBase>>;

/** Assemble the Built result for a single-pair autonomous scenario (verify both legs). */
async function finishAutonomous(b: AutoBase, l3a: L3Payment, l3b: L3Checkout, amount: string): Promise<Built> {
  const resolveIssuerKey = async () => b.issuer.publicJwk;
  const t = now();
  return {
    mode: "AUTONOMOUS",
    kids: { issuer: b.issuer.kid, user: b.user.kid, agent: b.agent.kid },
    l1: b.l1, l2: b.l2, l3a, l3b, networkView: b.networkView, merchantView: b.merchantView,
    networkSees: await mandateVcts(b.networkView),
    merchantSees: await mandateVcts(b.merchantView),
    networkResult: await verifyChain({ l1: b.l1, l2: b.l2, l3Payment: l3a, resolveIssuerKey, now: t, l2PaymentSerialized: b.networkView.serialized }),
    merchantResult: await verifyChain({ l1: b.l1, l2: b.l2, l3Checkout: l3b, resolveIssuerKey, now: t, l2CheckoutSerialized: b.merchantView.serialized }),
    payment: { amount, payee: "Tennis Warehouse", txId: b.cHash },
    limits: { cap: "$400.00", merchant: "Tennis Warehouse", item: "Babolat Pure Drive" },
  };
}

const SETUP_STEP = (situation: string): StepMeta => ({ id: "setup", actor: "user", title: "The situation", situation });

const AUTONOMOUS_STEPS = (opts: { verify: string; l3?: string; l3Title?: string; setup?: string }): StepMeta[] => [
  SETUP_STEP(
    opts.setup ??
      "Alice wants her AI shopping agent to buy a tennis racket for her — but only under $400, and only from a store she trusts. She never hands the agent her card; she hands it a cryptographic mandate.",
  ),
  {
    id: "l1",
    actor: "issuer",
    title: "The bank issues Alice a credential (L1)",
    situation:
      "Alice's bank signs an SD-JWT that binds her card to her own key (`cnf`). This is the root of trust — everything downstream must chain back to it. It stays in Alice's wallet.",
    transfer: { from: "issuer", to: "user", what: "L1 credential" },
  },
  {
    id: "l2",
    actor: "user",
    title: "Alice delegates to the agent, with constraints (L2)",
    situation:
      "Alice signs a mandate that authorizes her agent's key to act — but only within limits: ≤ $400, one racket, from an approved merchant. She hands this to the agent. The agent cannot exceed these bounds.",
    transfer: { from: "user", to: "agent", what: "L2 mandate (constraints + agent delegation)" },
  },
  {
    id: "l3",
    actor: "agent",
    title: opts.l3Title ?? "The agent shops and produces proof (L3)",
    situation:
      opts.l3 ??
      "The agent picks a racket within the rules, gets a signed checkout from the merchant, and creates two proofs: L3a (payment) for the network and L3b (checkout) for the merchant. Each is signed by the agent's delegated key.",
    active: ["merchant", "network"],
  },
  {
    id: "route",
    actor: "agent",
    title: "Who receives what — and how it's submitted",
    situation:
      "This is the privacy boundary. Each verifier is handed a bundle of THREE SD-JWTs together — L1 + a tailored view of L2 + its L3 leg. The network's bundle carries the payment (no cart); the merchant's carries the cart (no card or amount). Below are the actual serialized credentials each one receives.",
    active: ["merchant", "network"],
  },
  { id: "verify", actor: "network", title: "Everyone verifies independently", situation: opts.verify, active: ["merchant"] },
];

const STRINGS: Item = { id: "STR001", sku: "STR001", title: "Luxilon String Set" };

async function buildMultiPair(): Promise<Built> {
  const { issuer, user, t, l1 } = await issuerAndUser();
  const agent = await generateViKeyPair();
  const racketPair = {
    checkoutConstraints: [
      { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: MERCHANTS },
      { type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-racket", acceptable_items: [ITEMS[0]!], quantity: 1 }] },
    ] as Constraint[],
    paymentConstraints: [
      { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 },
      { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: MERCHANTS },
    ] as Constraint[],
    paymentInstrument: PI,
  };
  const subPair = {
    checkoutConstraints: [
      { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: MERCHANTS },
      { type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-strings", acceptable_items: [STRINGS], quantity: 1 }] },
    ] as Constraint[],
    paymentConstraints: [
      { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 100, max: 3000 },
      { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: MERCHANTS },
      { type: CONSTRAINT_TYPE.RECURRENCE, frequency: "MNTH", start_date: "2026-01-01", number: 12 },
    ] as Constraint[],
    paymentInstrument: PI,
  };
  const l2 = await issueL2AutonomousMultiPair({
    l1, aud: "agent://alice-shopping-bot", nonce: crypto.randomUUID(), iat: t, exp: t + 86_400,
    userPrivateKey: user.privateKey, userKid: user.kid,
    agentPublicJwk: agent.publicJwk, agentKid: agent.kid,
    merchants: MERCHANTS, acceptableItems: [ITEMS[0]!, STRINGS], pairs: [racketPair, subPair],
  });

  const l2Base = baseJwtOf(l2.serialized);
  const isVct = (vct: string) => (v: unknown) => (v as any)?.vct === vct;
  const payments = findDisclosures(l2, isVct(VI_VCT.PAYMENT_OPEN));
  const checkouts = findDisclosures(l2, isVct(VI_VCT.CHECKOUT_OPEN));
  const merchant0 = findDisclosures(l2, (v) => !!(v as any)?.website && !(v as any)?.vct)[0]!;
  const item0 = findDisclosures(l2, (v) => !!(v as any)?.sku && !(v as any)?.vct)[0]!;

  const amounts = [25000, 2500]; // $250 racket, $25/mo strings
  const splitL3s: SplitL3[] = [];
  let l3a: ViLayer | undefined;
  let l3b: ViLayer | undefined;
  for (let i = 0; i < 2; i++) {
    const cart = `eyJhbGciOiJFUzI1NiJ9.cart-${i}.sig`;
    const cHash = await checkoutHash(cart);
    const netView = await encodePresentation(l2Base, [payments[i]!.encoded, merchant0.encoded]);
    const merView = await encodePresentation(l2Base, [checkouts[i]!.encoded, item0.encoded]);
    const l3Payment = await issueL3Payment({
      nonce: `n${i}`, aud: "https://network.example", iat: t, exp: t + 300,
      agentPrivateKey: agent.privateKey, agentKid: agent.kid, l2BaseJwt: l2Base,
      transactionId: cHash, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: amounts[i]! },
      paymentInstrument: PI, finalMerchant: MERCHANTS[0]!,
      l2PaymentDisclosure: payments[i]!.encoded, l2MerchantDisclosure: merchant0.encoded,
    });
    const l3Checkout = await issueL3Checkout({
      nonce: `n${i}`, aud: "https://tw.example", iat: t, exp: t + 300,
      agentPrivateKey: agent.privateKey, agentKid: agent.kid, l2BaseJwt: l2Base,
      checkoutJwt: cart, checkoutHash: cHash,
      l2CheckoutDisclosure: checkouts[i]!.encoded, l2ItemDisclosure: item0.encoded,
    });
    splitL3s.push({ l3Payment, l3Checkout, l2PaymentSerialized: netView, l2CheckoutSerialized: merView });
    if (i === 0) { l3a = l3Payment; l3b = l3Checkout; }
  }

  const verify = await verifyChain({ l1, l2, splitL3s, resolveIssuerKey: async () => issuer.publicJwk, now: now() });
  return {
    mode: "AUTONOMOUS", kids: { issuer: issuer.kid, user: user.kid, agent: agent.kid },
    l1, l2, l3a, l3b, networkResult: verify,
    pairCount: verify.mandatePairCount,
    networkEnforced: (verify.networkEnforced ?? []).map((n) => n.type),
    payment: { amount: "$250.00 one-off + $25.00/mo", payee: "Tennis Warehouse", txId: "" },
    limits: { cap: "racket ≤ $400 · strings ≤ $30/mo", merchant: "Tennis Warehouse", item: "racket + string subscription" },
  };
}

const MULTIPAIR: ScenarioDef = {
  id: "multipair",
  icon: "📅",
  title: "One-off + subscription",
  tagline: "Autonomous · 2 mandate pairs",
  outcome: "success",
  facts: [
    { label: "Intent", value: "Buy a racket now, and subscribe to monthly strings" },
    { label: "Pair 0", value: "Racket — $250.00 (one-off)" },
    { label: "Pair 1", value: "Strings — $25.00 / month (recurring)" },
  ],
  steps: [
    SETUP_STEP(
      "One delegation can authorize several distinct purchases at once — here a one-off racket AND a monthly string subscription. Each is its own mandate pair with its own rules.",
    ),
    {
      id: "l1", actor: "issuer", title: "The bank issues Alice a credential (L1)",
      situation: "Same root credential as every other flow.",
      transfer: { from: "issuer", to: "user", what: "L1 credential" },
    },
    {
      id: "l2", actor: "user", title: "One mandate, two pairs (L2)",
      situation:
        "Alice signs a single L2 holding two independent checkout+payment pairs — pair 0 (racket, ≤ $400, one-off) and pair 1 (strings, ≤ $30, recurring monthly). The agent fulfills each on its own.",
      transfer: { from: "user", to: "agent", what: "L2 with 2 mandate pairs" },
    },
    {
      id: "l3", actor: "agent", title: "The agent fulfills each pair",
      situation:
        "The agent produces a split L3 for each pair. The verifier matches them positionally and checks every pair's constraints separately (shown: pair 0). Duplicate or orphaned pairs are rejected.",
      active: ["merchant", "network"],
    },
    {
      id: "verify", actor: "network", title: "Verify all pairs — and flag the stateful rule",
      situation:
        "Both pairs verify. The monthly `recurrence` rule is network-enforced: a stateless verifier can't track it across months, so the library surfaces it for the payment network to enforce with its own state.",
      active: ["merchant"],
    },
  ],
  build: buildMultiPair,
};

async function buildSwap(): Promise<Built> {
  const b = await autonomousBase();
  const cartMerchant = "eyJhbGciOiJFUzI1NiJ9.cart-shown-to-merchant.sig";
  const cHashMerchant = await checkoutHash(cartMerchant);
  const cartBilled = "eyJhbGciOiJFUzI1NiJ9.different-cart-billed.sig";
  const cHashBilled = await checkoutHash(cartBilled); // DIFFERENT transaction than the merchant's cart
  const l3a = await issueL3Payment({
    nonce: "l3", aud: "https://network.example", iat: b.t, exp: b.t + 300,
    agentPrivateKey: b.agent.privateKey, agentKid: b.agent.kid, l2BaseJwt: b.l2Base,
    transactionId: cHashBilled, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: 25000 },
    paymentInstrument: PI, finalMerchant: MERCHANTS[0]!,
    l2PaymentDisclosure: b.networkView.disclosures[0], l2MerchantDisclosure: b.networkView.disclosures[1],
  });
  const l3b = await issueL3Checkout({
    nonce: "l3", aud: "https://tw.example", iat: b.t, exp: b.t + 300,
    agentPrivateKey: b.agent.privateKey, agentKid: b.agent.kid, l2BaseJwt: b.l2Base,
    checkoutJwt: cartMerchant, checkoutHash: cHashMerchant,
    l2CheckoutDisclosure: b.merchantView.disclosures[0], l2ItemDisclosure: b.merchantView.disclosures[1],
  });
  const t = now();
  const resolveIssuerKey = async () => b.issuer.publicJwk;
  return {
    mode: "AUTONOMOUS",
    kids: { issuer: b.issuer.kid, user: b.user.kid, agent: b.agent.kid },
    l1: b.l1, l2: b.l2, l3a, l3b, networkView: b.networkView, merchantView: b.merchantView,
    networkSees: await mandateVcts(b.networkView), merchantSees: await mandateVcts(b.merchantView),
    // Cross-checked over BOTH legs: each is valid alone, but they reference different transactions.
    networkResult: await verifyChain({
      l1: b.l1, l2: b.l2, l3Payment: l3a, l3Checkout: l3b, resolveIssuerKey, now: t,
      l2PaymentSerialized: b.networkView.serialized, l2CheckoutSerialized: b.merchantView.serialized,
    }),
    payment: { amount: "billed for a different cart", payee: "Tennis Warehouse", txId: cHashBilled },
    limits: { cap: "$400.00", merchant: "Tennis Warehouse", item: "Babolat Pure Drive" },
  };
}

const SWAP: ScenarioDef = {
  id: "swap",
  icon: "🔀",
  title: "Cart / payment swap",
  tagline: "Autonomous · binding broken · REJECTED",
  outcome: "blocked",
  facts: [
    { label: "Intent", value: "Buy 1 racket, ≤ $400" },
    { label: "Attack", value: "Bill the network for a different cart than the merchant sees" },
    { label: "Expected", value: "checkout_hash ≠ transaction_id → rejected" },
  ],
  steps: AUTONOMOUS_STEPS({
    l3Title: "The agent mismatches the two proofs (L3)",
    l3: "Here's the trick: the agent builds the payment proof (L3a) bound to transaction A — a different, pricier cart — but the checkout proof (L3b) for transaction B, the cart it actually shows the merchant. BOTH proofs are validly signed. It's betting each verifier only ever sees its own half.",
    verify:
      "Alone, each leg checks out — that's what makes this sneaky. But the payment and checkout must reference the SAME transaction (`transaction_id` = `checkout_hash`). Cross-check the two and they disagree (A ≠ B) — so the linked chain is rejected.",
  }),
  build: buildSwap,
};

export const SCENARIOS: ScenarioDef[] = [
  // 1 — Autonomous happy path -------------------------------------------------
  {
    id: "autonomous",
    icon: "🎾",
    title: "Buy a racket under $400",
    tagline: "Autonomous · 3 layers · happy path",
    outcome: "success",
    facts: [
      { label: "Intent", value: "Buy 1 tennis racket, ≤ $400, approved store" },
      { label: "Agent picks", value: "Babolat Pure Drive — $250.00" },
      { label: "Merchant", value: "Tennis Warehouse" },
    ],
    steps: AUTONOMOUS_STEPS({
      verify:
        "The network checks the payment proof against Alice's constraints ($250 ≤ $400 ✓, approved payee ✓) and the signature chain. The merchant checks the checkout proof. Both pass — the purchase is authorized.",
    }),
    build: async () => {
      const b = await autonomousBase();
      const l3a = await issueL3Payment({
        nonce: "l3", aud: "https://network.example", iat: b.t, exp: b.t + 300,
        agentPrivateKey: b.agent.privateKey, agentKid: b.agent.kid, l2BaseJwt: b.l2Base,
        transactionId: b.cHash, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: 25000 },
        paymentInstrument: PI, finalMerchant: MERCHANTS[0]!,
        l2PaymentDisclosure: b.networkView.disclosures[0], l2MerchantDisclosure: b.networkView.disclosures[1],
      });
      const l3b = await issueL3Checkout({
        nonce: "l3", aud: "https://tw.example", iat: b.t, exp: b.t + 300,
        agentPrivateKey: b.agent.privateKey, agentKid: b.agent.kid, l2BaseJwt: b.l2Base,
        checkoutJwt: CART_JWT, checkoutHash: b.cHash,
        l2CheckoutDisclosure: b.merchantView.disclosures[0], l2ItemDisclosure: b.merchantView.disclosures[1],
      });
      return finishAutonomous(b, l3a, l3b, "$250.00");
    },
  },

  // 2 — Immediate happy path --------------------------------------------------
  {
    id: "immediate",
    icon: "🛒",
    title: "Approve this exact $42 cart",
    tagline: "Immediate · 2 layers · human-confirmed",
    outcome: "success",
    facts: [
      { label: "Intent", value: "Confirm one specific cart" },
      { label: "Amount", value: "$42.00 (final, user-signed)" },
      { label: "Merchant", value: "Tennis Warehouse" },
    ],
    steps: [
      SETUP_STEP(
        "Sometimes there's no constraint to delegate — the user is right there and confirms an exact cart. In Immediate mode Alice signs the final values herself; the agent only forwards them.",
      ),
      {
        id: "l1", actor: "issuer", title: "The bank issues Alice a credential (L1)",
        situation: "Same root credential as before — Alice's card bound to her key, in her wallet.",
        transfer: { from: "issuer", to: "user", what: "L1 credential" },
      },
      {
        id: "l2", actor: "user", title: "Alice signs the final cart + amount (L2)",
        situation:
          "No constraints, no agent delegation. Alice signs the exact checkout and the exact $42.00 payment. The checkout and payment are cryptographically cross-linked so the amount can't be swapped for the cart.",
        transfer: { from: "user", to: "agent", what: "L2 with final values" },
      },
      {
        id: "verify", actor: "network", title: "Verifiers confirm the final values",
        situation:
          "The agent forwards L1 + L2. The verifier checks the signature chain and that the amount matches the cart (`checkout_hash` = `transaction_id`). No L3, no constraints — the human already decided.",
        active: ["merchant"],
      },
    ],
    build: async () => {
      const { issuer, user, t, l1 } = await issuerAndUser();
      const l2 = await issueL2Immediate({
        l1, aud: "agent://alice-shopping-bot", nonce: crypto.randomUUID(), iat: t, exp: t + 900,
        userPrivateKey: user.privateKey, userKid: user.kid,
        checkoutJwt: CART_JWT, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: 4200 }, paymentInstrument: PI,
      });
      return {
        mode: "IMMEDIATE", kids: { issuer: issuer.kid, user: user.kid }, l1, l2,
        networkResult: await verifyChain({ l1, l2, resolveIssuerKey: async () => issuer.publicJwk, now: now() }),
        payment: { amount: "$42.00", payee: "Tennis Warehouse", txId: "" },
      };
    },
  },

  // 3 — Multi-pair: one-off + subscription (success) --------------------------
  MULTIPAIR,

  // 4 — Blocked: overspend ----------------------------------------------------
  {
    id: "overspend",
    icon: "🚫",
    title: "Agent tries to overspend",
    tagline: "Autonomous · constraint violated · BLOCKED",
    outcome: "blocked",
    facts: [
      { label: "Intent", value: "Buy 1 racket, ≤ $400" },
      { label: "Agent attempts", value: "$999.00 payment" },
      { label: "Expected", value: "Network rejects it" },
    ],
    steps: AUTONOMOUS_STEPS({
      l3Title: "The agent overshoots the budget (L3)",
      l3: "The agent builds its payment proof — but sets the amount to $999.00, far above Alice's $400 cap. The signature over it is perfectly valid; the AMOUNT is what's out of bounds. It's betting the network won't re-check the mandate.",
      verify:
        "The network re-derives the constraint from Alice's signed L2 ($400 cap) and compares: $999 > $400. Rejected. A rogue or buggy agent cannot exceed the user's intent, even with a valid signature.",
    }),
    build: async () => {
      const b = await autonomousBase();
      const l3a = await issueL3Payment({
        nonce: "l3", aud: "https://network.example", iat: b.t, exp: b.t + 300,
        agentPrivateKey: b.agent.privateKey, agentKid: b.agent.kid, l2BaseJwt: b.l2Base,
        transactionId: b.cHash, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: 99900 }, // $999 > $400
        paymentInstrument: PI, finalMerchant: MERCHANTS[0]!,
        l2PaymentDisclosure: b.networkView.disclosures[0], l2MerchantDisclosure: b.networkView.disclosures[1],
      });
      const l3b = await issueL3Checkout({
        nonce: "l3", aud: "https://tw.example", iat: b.t, exp: b.t + 300,
        agentPrivateKey: b.agent.privateKey, agentKid: b.agent.kid, l2BaseJwt: b.l2Base,
        checkoutJwt: CART_JWT, checkoutHash: b.cHash,
        l2CheckoutDisclosure: b.merchantView.disclosures[0], l2ItemDisclosure: b.merchantView.disclosures[1],
      });
      return finishAutonomous(b, l3a, l3b, "$999.00");
    },
  },

  // 5 — Attack: forged agent key ---------------------------------------------
  {
    id: "forged",
    icon: "🕵️",
    title: "Forged agent key",
    tagline: "Autonomous · impostor signature · REJECTED",
    outcome: "blocked",
    facts: [
      { label: "Intent", value: "Buy 1 racket, ≤ $400" },
      { label: "Attack", value: "A different key signs L3 (same kid)" },
      { label: "Expected", value: "Signature check fails" },
    ],
    steps: AUTONOMOUS_STEPS({
      l3Title: "An impostor forges the proof (L3)",
      l3: "An attacker — not Alice's agent — assembles an L3 payment proof with believable values and even copies the agent's key id into the header, then signs it with their OWN key. At a glance it looks legitimate.",
      verify:
        "The network doesn't trust the key id in the L3 header. It resolves the ONLY authorized key from Alice's signed L2 `cnf` and checks the signature against that — which fails. The impostor's key was never delegated, so the chain breaks.",
    }),
    build: async () => {
      const b = await autonomousBase();
      const impostor = await generateViKeyPair();
      const l3a = await issueL3Payment({
        nonce: "l3", aud: "https://network.example", iat: b.t, exp: b.t + 300,
        agentPrivateKey: impostor.privateKey, agentKid: b.agent.kid, // impostor signs, but claims the agent's kid
        l2BaseJwt: b.l2Base, transactionId: b.cHash, payee: MERCHANTS[0]!, paymentAmount: { currency: "USD", amount: 25000 },
        paymentInstrument: PI, finalMerchant: MERCHANTS[0]!,
        l2PaymentDisclosure: b.networkView.disclosures[0], l2MerchantDisclosure: b.networkView.disclosures[1],
      });
      const l3b = await issueL3Checkout({
        nonce: "l3", aud: "https://tw.example", iat: b.t, exp: b.t + 300,
        agentPrivateKey: b.agent.privateKey, agentKid: b.agent.kid, l2BaseJwt: b.l2Base,
        checkoutJwt: CART_JWT, checkoutHash: b.cHash,
        l2CheckoutDisclosure: b.merchantView.disclosures[0], l2ItemDisclosure: b.merchantView.disclosures[1],
      });
      return finishAutonomous(b, l3a, l3b, "$250.00");
    },
  },

  // 6 — Blocked: cart / payment swap -----------------------------------------
  SWAP,
];

export const ACTOR_META: Record<Actor, { label: string; icon: string }> = {
  issuer: { label: "Bank / Issuer", icon: "🏦" },
  user: { label: "Alice (User)", icon: "👤" },
  agent: { label: "AI Agent", icon: "🤖" },
  merchant: { label: "Merchant", icon: "🛍️" },
  network: { label: "Payment Network", icon: "💳" },
};

export type { RoleView, VerificationResult, ViLayer, ViKeyPair };
