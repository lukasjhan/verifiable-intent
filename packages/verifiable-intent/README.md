# verifiable-intent

Layered SD-JWT credentials for agentic commerce — a TypeScript implementation of the
[Verifiable Intent](https://github.com/agent-intent/verifiable-intent) (VI) v0.1-draft format.

```bash
npm install verifiable-intent
```

All SD-JWT mechanics — disclosures, digesting, packing, serialization, JWT signing — are delegated
to [`@sd-jwt/core`](https://www.npmjs.com/package/@sd-jwt/core). This package adds the VI
delegation model on top. ES256 only. Isomorphic (Node 20+ and browsers, via WebCrypto).

## Quick start (Immediate mode)

```ts
import {
  createCryptoProvider,
  generateViKeyPair,
  issueL1,
  issueL2Immediate,
  verifyChain,
  VI_VCT,
} from "verifiable-intent";

const crypto = createCryptoProvider();
const now = Math.floor(Date.now() / 1000);

const issuer = await generateViKeyPair();
const user = await generateViKeyPair();

// L1 — issuer binds a credential to the user's key (cnf = user key). `email` is selectively disclosable.
const l1 = await issueL1(
  {
    iss: "https://issuer.example",
    vct: VI_VCT.L1_CARD,
    userPublicJwk: user.publicJwk,
    iat: now,
    exp: now + 86_400,
    visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
    email: "alice@example.com",
    issuerPrivateKey: issuer.privateKey,
    issuerKid: issuer.kid,
  },
  crypto,
);

// L2 — user delegates final, confirmed values to the agent (no onward cnf).
const l2 = await issueL2Immediate(
  {
    l1,
    aud: "agent://shopping-bot",
    nonce: "n-123",
    iat: now,
    exp: now + 900,
    userPrivateKey: user.privateKey,
    userKid: user.kid,
    checkoutJwt: "eyJ...cart",
    payee: { id: "m1", name: "Acme", website: "https://acme.example" },
    paymentAmount: { currency: "USD", amount: 4200 }, // integer minor units
    paymentInstrument: { type: "card", id: "pi-1" },
  },
  crypto,
);

const result = await verifyChain(
  { l1, l2, resolveIssuerKey: async () => issuer.publicJwk, now },
  crypto,
);
// result.valid === true, result.mode === "IMMEDIATE"
```

Autonomous mode (`issueL2Autonomous` → `issueL3Payment` / `issueL3Checkout`) adds constraints and a
split L3; see `apps/demo` and the test suite for a full 3-layer walkthrough with selective routing.

## Module map

| Module | Responsibility |
|---|---|
| `constants` / `types` | `typ`/`vct`/constraint enums + decoded layer shapes |
| `crypto/webcrypto` | ES256 keys, `Signer`/`Hasher`, salt, thumbprint (the only raw-crypto module) |
| `crypto/disclosure` | VI wrappers over core's `Disclosure`: create/hash/`delegate_payload` refs, resolver |
| `crypto/sd-jwt` | `sdjwtFor`/`signSdJwt`/`encodePresentation`/`parseLayer` — core `SDJwtInstance`/`Jwt`/`SDJwt` |
| `crypto/hash` | `sdHash`, `checkoutHash` |
| `issuance/{issuer,user,agent}` | L1 / L2 (Immediate + Autonomous) / L3a + L3b |
| `presentation/selective` | per-recipient L2 views (merchant vs network) |
| `verification/chain` | signature · `sd_hash` · `typ` · `cnf` · mandate pairing · cross-ref · constraints |
| `constraints` | eight constraint types + PERMISSIVE/STRICT modes |

## How it maps to `@sd-jwt/core`

Everything SD-JWT-shaped goes through the library:

- **Issuance** — L1 and L3 use `SDJwtInstance.issue(payload, disclosureFrame)` (the library packs
  the disclosures). L2 uses `Jwt` + `SDJwt` (explicit disclosures) because its shared merchant/item
  disclosures and its staged `reference` (= hash of a prior disclosure) can't be expressed in a
  single `pack()` pass.
- **Disclosures** — `Disclosure` (encode + digest) for object-property (L1 `email`) and
  array-element (mandates, merchants, items) disclosures.
- **Serialization / parsing** — `SDJwt.encodeSDJwt()` (including the per-recipient L2 views) and
  `splitSdJwt` + `Jwt.decodeJWT`.

Two things are intentionally VI-side:

- **Raw crypto** — ES256 sign/verify, SHA-256, salt, and keys are WebCrypto, injected into core as
  the `Signer` / `Hasher` / `SaltGenerator` (the library delegates crypto by design).
- **Resolution** — VI ships its OWN resolver (not core's `getClaims`/`unpack`): VI deliberately
  shares one merchant/item disclosure across constraints, so the same digest appears in multiple
  array positions, which a strict RFC 9901 resolver rejects. Disclosure decoding/digesting still
  goes through core.

## Network-enforced constraints — OUT OF LIBRARY SCOPE

`mandate.payment.budget`, `mandate.payment.recurrence`, and `mandate.payment.agent_recurrence`
require **cross-transaction state** (cumulative spend, recurrence counters). A stateless verifier
cannot evaluate them, so **this library does NOT enforce them** — the payment network (the library
consumer) must, against its own state store.

`verifyChain` surfaces them for you instead of silently passing them:

```ts
const r = await verifyChain({ l1, l2, l3Payment, resolveIssuerKey, now, l2PaymentSerialized });
// r.valid === true means the STATELESS checks passed — NOT that the budget is ok.
for (const { pairIndex, type, constraint } of r.networkEnforced ?? []) {
  // Feed `constraint` to YOUR stateful engine (e.g. decrement a running budget).
}
```

Treat `valid: true` as "signatures, binding, and per-transaction constraints hold"; you still owe
the stateful check for anything in `networkEnforced`.

## Status

Implemented: L1/L2/L3 issuance, selective disclosure (`delegate_payload` + nested merchant/item
refs), split-L3 selective `sd_hash`, **multi-mandate-pair** chain verification (pairing, mandate-
smuggling + orphan detection, `card_id` cross-check), and the per-transaction constraint engine
(including `line_items` `match_mode` minimum/exact + per-id quantity caps). Covered by a 61-case
unit + e2e suite.

TODO: a real JWKS resolver (`iss`+`kid` → fetch + cache). Stateful budget/recurrence enforcement is
intentionally left to the caller (see above).

## License

Apache-2.0.
