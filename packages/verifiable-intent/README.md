# verifiable-intent

Layered SD-JWT credentials for agentic commerce — a TypeScript implementation of the
[Verifiable Intent](https://github.com/agent-intent/verifiable-intent) (VI) v0.1-draft format.

VI cryptographically binds an AI agent's commercial actions to a user's delegated purchase intent,
so a verifier can prove *"this payment really was within what the user authorized."* It is a
**credential format + delegation-chain verification rules**, not a transport protocol.

All SD-JWT mechanics are delegated to [`@sd-jwt/core`](https://www.npmjs.com/package/@sd-jwt/core);
this package adds the VI delegation model on top. ES256 only. Isomorphic (Node 20+ and browsers,
via WebCrypto — no Node-only dependencies).

> **Versioned to track the spec** — `0.1.x` implements VI `v0.1-draft`. See [Versioning](#versioning).

```bash
npm install verifiable-intent
```

**🔗 [Live demo](https://verifiable-intent.vercel.app)** — a guided, in-browser walkthrough of every flow.

## Features

- **L1/L2/L3 issuance** — Immediate (2-layer) and Autonomous (3-layer, agent delegation) modes.
- **Selective disclosure** — mandates + nested merchant/item references, and per-recipient L2 views.
- **Split-L3 `sd_hash`** binding each leg to only the L2 view its recipient receives.
- **Multi-mandate-pair verification** — mandate-smuggling and orphan detection, `card_id` cross-check.
- **Constraint engine** — eight constraint types, PERMISSIVE/STRICT modes, `line_items` `match_mode`.
- **Runs in Node.js and the browser** — SD-JWT via `@sd-jwt/core`, ES256 via WebCrypto, ESM + CJS,
  full TypeScript types.

## Contents

- [The model in 60 seconds](#the-model-in-60-seconds)
- [Quick start (Immediate mode)](#quick-start-immediate-mode)
- [Full walkthrough (Autonomous mode)](#full-walkthrough-autonomous-mode)
- [Verifying a chain](#verifying-a-chain)
- [Constraints](#constraints)
- [Selective disclosure & privacy](#selective-disclosure--privacy)
- [Multiple mandate pairs](#multiple-mandate-pairs)
- [Network-enforced constraints — your responsibility](#network-enforced-constraints--your-responsibility)
- [API reference](#api-reference)
- [Running the examples](#running-the-examples)
- [How it maps to @sd-jwt/core](#how-it-maps-to-sd-jwtcore)
- [Versioning](#versioning)

## The model in 60 seconds

Three layers, each a plain RFC 9901 SD-JWT, linked by `cnf` (key delegation) and `sd_hash` (byte
binding):

```
L1  issuer → user     typ sd+jwt         ~1yr    root credential; cnf.jwk = user key
L2  user   → agent    typ kb-sd-jwt[+kb]         mandate(s); Immediate or Autonomous
L3  agent  → verifier typ kb-sd-jwt       ~5min  split into L3a (payment) + L3b (checkout)
```

- **`cnf` (RFC 7800)** — each layer names the public key allowed to sign the *next* layer. L1's
  `cnf` = the user key; an Autonomous L2 mandate's `cnf` = the agent key; L3 has no `cnf` (terminal).
- **`sd_hash`** — each layer carries `B64U(SHA-256(...))` of the previous layer's exact serialized
  form, so a tampered upstream layer breaks the chain.
- **`delegate_payload`** — mandates ride as *array-element disclosures* referenced from this claim;
  they are never plaintext top-level claims.

**Two modes:**

| | Immediate | Autonomous |
|---|---|---|
| Layers | L1 + L2 | L1 + L2 + L3 |
| Human | confirms the final cart + amount | sets constraints only; agent acts alone |
| L2 holds | final `checkout_jwt` + final amount | `open` mandates with constraints + agent `cnf` |
| L3 | none | agent creates split L3a/L3b |

**Roles & keys:** the *issuer* signs L1; the *user* signs L2 (with the key L1's `cnf` names); the
*agent* signs L3 (with the key the L2 mandate's `cnf` names). Generate each with
`generateViKeyPair()`.

## Quick start (Immediate mode)

The user confirms final values; the agent just forwards them. No L3, no constraints.

```ts
import {
  generateViKeyPair, issueL1, issueL2Immediate, verifyChain, VI_VCT,
} from "verifiable-intent";

const now = Math.floor(Date.now() / 1000);
const issuer = await generateViKeyPair();
const user = await generateViKeyPair();

// L1 — issuer binds the user's key. `email` is selectively disclosable; the rest is always visible.
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

// L2 — the user confirms the final cart + payment. checkout_hash / transaction_id are derived from
// `checkoutJwt` and cross-linked automatically.
const l2 = await issueL2Immediate({
  l1,
  aud: "agent://shopping-bot",
  nonce: "user-nonce-1",
  iat: now,
  exp: now + 900,
  userPrivateKey: user.privateKey,
  userKid: user.kid,
  checkoutJwt: "eyJ...merchant-signed-cart",
  payee: { id: "m1", name: "Acme", website: "https://acme.example" },
  paymentAmount: { currency: "USD", amount: 4200 }, // integer minor units (cents)
  paymentInstrument: { type: "card", id: "pi-1" },
});

const result = await verifyChain({
  l1, l2,
  resolveIssuerKey: async () => issuer.publicJwk, // real impl: fetch JWKS by iss+kid
  now,
});
// result.valid === true, result.mode === "IMMEDIATE"
```

## Full walkthrough (Autonomous mode)

The user delegates *constraints* to the agent, which then shops, obtains a merchant checkout, and
produces the split L3 — one leg for the payment network, one for the merchant. This is the complete
runnable [`examples/autonomous-flow.ts`](./examples/autonomous-flow.ts).

```ts
import {
  generateViKeyPair, issueL1, issueL2Autonomous, issueL3Payment, issueL3Checkout,
  presentL2ForNetwork, presentL2ForMerchant, verifyChain,
  baseJwtOf, checkoutHash, CONSTRAINT_TYPE, VI_VCT,
  type Merchant, type Item, type PaymentInstrument,
} from "verifiable-intent";

const now = Math.floor(Date.now() / 1000);
const MERCHANTS: Merchant[] = [{ id: "m1", name: "Tennis Warehouse", website: "https://tw.example" }];
const ITEMS: Item[] = [{ id: "BAB86345", sku: "BAB86345", title: "Babolat Pure Drive" }];
const PI: PaymentInstrument = { type: "card", id: "pi-1" };

const issuer = await generateViKeyPair();
const user = await generateViKeyPair();
const agent = await generateViKeyPair();

// 1. ISSUER → L1 (same as Immediate).
const l1 = await issueL1({
  iss: "https://issuer.example", vct: VI_VCT.L1_CARD, userPublicJwk: user.publicJwk,
  iat: now, exp: now + 86_400, visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
  email: "alice@example.com", issuerPrivateKey: issuer.privateKey, issuerKid: issuer.kid,
});

// 2. USER → L2: constraints + delegate to the agent key (embedded as each mandate's cnf).
const l2 = await issueL2Autonomous({
  l1, aud: "agent://shopping-bot", nonce: "user-nonce-1", iat: now, exp: now + 86_400,
  userPrivateKey: user.privateKey, userKid: user.kid,
  agentPublicJwk: agent.publicJwk, agentKid: agent.kid,
  promptSummary: "Buy a Babolat tennis racket under $400",
  merchants: MERCHANTS,          // shared pool of merchant disclosures
  acceptableItems: ITEMS,        // shared pool of item disclosures
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

// 3. AGENT → obtains a merchant-signed checkout, builds the selective L2 views, and issues split L3.
const checkoutJwt = "eyJ...merchant-signed-cart";
const cHash = await checkoutHash(checkoutJwt);
const l2Base = baseJwtOf(l2.serialized);

const netView = await presentL2ForNetwork(l2); // payment mandate + selected merchant
const merView = await presentL2ForMerchant(l2); // checkout mandate + selected item

const l3a = await issueL3Payment({
  nonce: "agent-nonce-1", aud: "https://network.example", iat: now, exp: now + 300,
  agentPrivateKey: agent.privateKey, agentKid: agent.kid, l2BaseJwt: l2Base,
  transactionId: cHash, payee: MERCHANTS[0], paymentAmount: { currency: "USD", amount: 25000 },
  paymentInstrument: PI, finalMerchant: MERCHANTS[0],
  l2PaymentDisclosure: netView.disclosures[0], l2MerchantDisclosure: netView.disclosures[1],
});

const l3b = await issueL3Checkout({
  nonce: "agent-nonce-1", aud: "https://tw.example", iat: now, exp: now + 300,
  agentPrivateKey: agent.privateKey, agentKid: agent.kid, l2BaseJwt: l2Base,
  checkoutJwt, checkoutHash: cHash,
  l2CheckoutDisclosure: merView.disclosures[0], l2ItemDisclosure: merView.disclosures[1],
});

// 4. NETWORK verifies the payment chain + constraints (sees only the payment leg).
const resolveIssuerKey = async () => issuer.publicJwk;
const network = await verifyChain({ l1, l2, l3Payment: l3a, resolveIssuerKey, now, l2PaymentSerialized: netView.serialized });

// 5. MERCHANT verifies the checkout chain (sees only the checkout leg).
const merchant = await verifyChain({ l1, l2, l3Checkout: l3b, resolveIssuerKey, now, l2CheckoutSerialized: merView.serialized });

console.log(network.valid, merchant.valid); // true true
```

### What the agent must pass to `verifyChain`

The split-L3 `sd_hash` binds each leg to the **exact L2 view** its recipient received. So the
verifier must be given that same view string:

- Network verify → `l2PaymentSerialized: netView.serialized`
- Merchant verify → `l2CheckoutSerialized: merView.serialized`

`presentL2For…` returns `{ serialized, disclosures }`; feed `serialized` to the verifier and the two
`disclosures` to the matching `issueL3…` call (payment+merchant for L3a, checkout+item for L3b).

## Verifying a chain

`verifyChain(params)` returns a structured [`VerificationResult`](#verificationresult) and **never
throws** for a bad credential — inspect `result.valid` and `result.errors`.

```ts
const r = await verifyChain({
  l1, l2,
  l3Payment,                 // Autonomous network side
  l3Checkout,                // Autonomous merchant side (either/both/neither)
  l2PaymentSerialized,       // the L2 view L3a was bound to
  l2CheckoutSerialized,      // the L2 view L3b was bound to
  resolveIssuerKey: async (iss, kid) => fetchJwks(iss, kid), // you supply this
  now: Math.floor(Date.now() / 1000),
  clockSkewSeconds: 300,     // default
  strictness: "PERMISSIVE",  // or "STRICT" for unknown constraint types
});

if (!r.valid) throw new Error(r.errors.join("; "));
```

What it checks (fail-closed, in order): ES256 signatures per layer · `typ` per layer · L1 `vct` +
expiry · L2 `sd_hash` binds to L1 · mode inferred from mandate VCTs · mandate pairing (with
duplicate-ref / orphan detection) · `card_id` ↔ `payment_instrument.id` · per-mode mandate rules ·
agent key resolved from the L2 `cnf` (never from the L3 header) and identical across pairs · L3
`sd_hash` binds to its L2 view · L3 has no `cnf` · L3 lifetime ≤ 1h · L3 → mandate-pair binding ·
cross-reference (`transaction_id == checkout_hash`) · per-transaction constraints.

`resolveIssuerKey(iss, kid)` is **yours to implement** — fetch the issuer's JWKS by `iss`+`kid`
(not `/.well-known/jwt-vc-issuer`), cache it (TTL ≤ 24h), pin the cert.

## Constraints

Constraints live only in **Autonomous** L2 mandates. Eight types:

| Type (`CONSTRAINT_TYPE.…`) | Mandate | Fields | Enforced by |
|---|---|---|---|
| `ALLOWED_MERCHANTS` | checkout | `allowed: Merchant[]` | verifier |
| `LINE_ITEMS` | checkout | `items: [{ id, acceptable_items: Item[], quantity }]`, `match_mode?` | verifier |
| `ALLOWED_PAYEES` | payment | `allowed: Merchant[]` | verifier |
| `AMOUNT_RANGE` | payment | `currency`, `min?`, `max?` (minor units) | verifier |
| `BUDGET` | payment | `currency`, `max`, `min?` | **network (stateful)** |
| `RECURRENCE` | payment | `frequency`, `start_date`, `end_date?`, `number?` | **network (stateful)** |
| `AGENT_RECURRENCE` | payment | `frequency`, `start_date`, `end_date`, `max_occurrences?` | **network (stateful)** |
| `REFERENCE` | payment | `conditional_transaction_id` | auto-injected by issuance |

You pass merchants/items **inline** in the constraints; issuance rewrites them into selective
`{"...": digest}` references against the shared `merchants` / `acceptableItems` pools.

**`LINE_ITEMS.match_mode`:**
- `"minimum"` (default) — subset semantics: everything bought must be acceptable and within the
  total + per-id quantity caps; buying fewer/none of a requirement is fine.
- `"exact"` — additionally, every non-wildcard requirement must be covered by a bought item with
  quantity > 0. An empty `acceptable_items` is a wildcard (any SKU) and is skipped for coverage.

**Strictness** (unknown constraint types): `PERMISSIVE` (default) skips them; `STRICT` rejects them;
an unknown constraint on an `open` mandate is **always** rejected regardless of mode. Override
per-type with `checkConstraints(…, { constraintPolicy: { "urn:x:y": "STRICT" } })`.

You can also run the checker directly:

```ts
import { checkConstraints, CONSTRAINT_TYPE } from "verifiable-intent";
const res = checkConstraints(
  [{ type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 }],
  { payment_amount: { currency: "USD", amount: 25000 } },
);
// res => { satisfied, violations, checked, skipped }
```

## Selective disclosure & privacy

Because each layer is a plain SD-JWT, a "view" is the same signed base JWT re-serialized with a
subset of disclosures. The library gives you role views:

```ts
const netView = await presentL2ForNetwork(l2); // payment mandate + a merchant; NO checkout
const merView = await presentL2ForMerchant(l2); // checkout mandate + an item; NO payment
```

By default the first merchant/item disclosure is revealed; pass a predicate to choose another
(`presentL2ForNetwork(l2, (v) => v.id === "m2")`). To inspect what a party can see, parse and
resolve the view:

```ts
import { parseLayer, resolveDisclosures } from "verifiable-intent";
const v = await parseLayer(netView.serialized);
const claims = await resolveDisclosures(v.payload, v.disclosureStrings);
// claims.delegate_payload contains only the payment mandate; the checkout ref stays unresolved.
```

## Multiple mandate pairs

One L2 can authorize several independent checkout+payment pairs (e.g. a subscription *and* a
one-off). Issue with `issueL2AutonomousMultiPair`, then verify with `splitL3s` — one entry per pair,
positionally matched:

```ts
import { issueL2AutonomousMultiPair, verifyChain, type SplitL3 } from "verifiable-intent";

const l2 = await issueL2AutonomousMultiPair({
  l1, aud, nonce, iat, exp, userPrivateKey, userKid, agentPublicJwk, agentKid,
  merchants: MERCHANTS, acceptableItems: ITEMS,
  pairs: [
    { checkoutConstraints: [...], paymentConstraints: [...], paymentInstrument: PI },
    { checkoutConstraints: [...], paymentConstraints: [...], paymentInstrument: PI },
  ],
});

const splitL3s: SplitL3[] = [
  { l3Payment: l3a0, l3Checkout: l3b0, l2PaymentSerialized: view0.serialized, l2CheckoutSerialized: mview0.serialized },
  { l3Payment: l3a1, l3Checkout: l3b1, l2PaymentSerialized: view1.serialized, l2CheckoutSerialized: mview1.serialized },
];
const r = await verifyChain({ l1, l2, splitL3s, resolveIssuerKey, now });
// r.mandatePairCount === 2
```

Pairing is hardened against **mandate smuggling** (duplicate disclosure references) and **orphaned**
mandates (a payment referencing a missing checkout, or vice-versa) — both are rejected.

## Network-enforced constraints — your responsibility

`BUDGET`, `RECURRENCE`, and `AGENT_RECURRENCE` need **cross-transaction state** (cumulative spend,
recurrence counters) that a stateless verifier cannot hold. **This library does not enforce them.**
Instead, `verifyChain` surfaces them so you can feed your own state engine:

```ts
const r = await verifyChain({ l1, l2, l3Payment, resolveIssuerKey, now, l2PaymentSerialized });
// r.valid === true means the STATELESS checks passed — NOT that the budget is ok.
for (const { pairIndex, type, constraint } of r.networkEnforced ?? []) {
  // e.g. decrement a running per-user budget, check recurrence windows, etc.
}
```

Treat `valid: true` as "signatures, binding, and per-transaction constraints hold"; you still owe
the stateful check for everything in `networkEnforced`.

## API reference

**Keys** — `generateViKeyPair()` → `{ privateKey, publicJwk, kid }` · `importPublicKey(jwk)` ·
`jwkThumbprint(jwk)` · `toCnf(publicJwk)`.

**Issuance** — `issueL1` · `issueL2Immediate` · `issueL2Autonomous` · `issueL2AutonomousMultiPair` ·
`issueL3Payment` · `issueL3Checkout`. All are async and return a parsed layer
(`{ serialized, header, payload, disclosures, disclosureStrings }`).

**Presentation** — `presentL2ForNetwork(l2, merchant?)` · `presentL2ForMerchant(l2, item?)` →
`{ serialized, disclosures: [string, string] }` · `present(layer, keepIndices)` ·
`findDisclosure(s)`.

**Verification** — `verifyChain(params)` → `VerificationResult` · `checkConstraints(constraints,
fulfillment, opts?)` → `{ satisfied, violations, checked, skipped }`.

**Crypto / SD-JWT** — `sha256` · `sdHash` · `checkoutHash` · `parseLayer` · `baseJwtOf` ·
`resolveDisclosures` · `encodePresentation` · `createDisclosure` · `hashDisclosure` ·
`sdjwtFor` · `signSdJwt`.

**Constants** — `VI_VCT` · `VI_TYP` · `CONSTRAINT_TYPE` · `STRICTNESS` ·
`NETWORK_ENFORCED_CONSTRAINTS` · `VI_ALG` (`"ES256"`) · `DEFAULT_CLOCK_SKEW_SECONDS`.

### `VerificationResult`

```ts
interface VerificationResult {
  valid: boolean;
  errors: string[];
  mode?: "IMMEDIATE" | "AUTONOMOUS";
  checksPerformed: string[];
  checksSkipped: string[];
  l1Claims?: Record<string, unknown>;
  l2Claims?: Record<string, unknown>;
  l3PaymentClaims?: Record<string, unknown>;   // first pair (back-compat)
  l3CheckoutClaims?: Record<string, unknown>;
  mandatePairCount?: number;
  pairResults?: { l3PaymentClaims?: unknown; l3CheckoutClaims?: unknown }[];
  networkEnforced?: { pairIndex: number; type: string; constraint: Constraint }[];
}
```

## Running the examples

Node 22.6+ strips the types, so the `.ts` examples run directly:

```bash
node examples/immediate-flow.ts       # or: pnpm example:immediate
node examples/autonomous-flow.ts      # or: pnpm example:autonomous
```

## How it maps to `@sd-jwt/core`

Everything SD-JWT-shaped goes through the library:

- **Issuance** — L1 and L3 use `SDJwtInstance.issue(payload, disclosureFrame)`. L2 uses `Jwt` +
  `SDJwt` (explicit disclosures) because its shared merchant/item disclosures and its staged
  `reference` (= hash of a prior disclosure) can't be expressed in a single `pack()` pass.
- **Disclosures** — `Disclosure` (encode + digest) for object-property (L1 `email`) and
  array-element (mandates, merchants, items) disclosures.
- **Serialization / parsing** — `SDJwt.encodeSDJwt()` (incl. the per-recipient L2 views) and
  `splitSdJwt` + `Jwt.decodeJWT`.

Two things are intentionally VI-side:

- **Raw crypto** — ES256 sign/verify, SHA-256, salt, and keys are WebCrypto, injected into core as
  the `Signer` / `Hasher` / `SaltGenerator` (the library delegates crypto by design).
- **Resolution** — VI ships its own resolver (not core's `getClaims`/`unpack`): VI deliberately
  shares one merchant/item disclosure across constraints, so the same digest appears in multiple
  array positions, which a strict RFC 9901 resolver rejects. Disclosure decoding/digesting still
  goes through core.

## Versioning

The library version tracks the [VI spec](https://github.com/agent-intent/verifiable-intent) version
it implements. **`0.1.x` implements VI `v0.1-draft`.** Patch releases are library-side changes
against the same spec draft; the minor/major moves with the spec (e.g. spec `v0.2` → library
`0.2.x`, spec `v1.0` → library `1.0.0`). See [`CHANGELOG.md`](./CHANGELOG.md).

## License

[Apache-2.0](../../LICENSE), matching the upstream
[`agent-intent/verifiable-intent`](https://github.com/agent-intent/verifiable-intent) reference.
