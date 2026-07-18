# Verifiable Intent (VI) — TypeScript

A TypeScript implementation of the [**Verifiable Intent**](https://github.com/agent-intent/verifiable-intent)
credential format (v0.1-draft): layered SD-JWT credentials that cryptographically bind an AI
agent's commercial actions to a user's delegated purchase intent.

> **What VI is** — not a transport protocol (that's AP2 / OpenID4VP), but a *credential format +
> delegation-chain verification rules*. Three layers, linked by `cnf` (key delegation) and
> `sd_hash` (byte binding):
>
> ```
> L1  issuer → user     (sd+jwt,        ~1yr)   root credential, cnf = user key
> L2  user   → agent     (kb-sd-jwt[+kb])        mandate(s), Immediate or Autonomous
> L3  agent  → verifier  (kb-sd-jwt,     ~5min)  split L3a (payment) + L3b (checkout)
> ```
>
> Every layer is a plain RFC 9901 SD-JWT; key-binding claims live in each layer's payload, and each
> layer is signed by the key named in the previous layer's `cnf`.

## Features

- **L1/L2/L3 issuance** in two modes — Immediate (2-layer) and Autonomous (3-layer, agent delegation).
- **Selective disclosure** — mandates + nested merchant/item references, and per-recipient L2 views
  (the merchant sees checkout, the network sees payment).
- **Split-L3 `sd_hash`** binding each leg to only the L2 view its recipient receives.
- **Multi-mandate-pair verification** with mandate-smuggling and orphan detection, plus a
  `card_id` ↔ `payment_instrument` cross-check.
- **Constraint engine** — eight constraint types, PERMISSIVE/STRICT modes, and `line_items`
  `match_mode` (minimum/exact).
- **SD-JWT via [`@sd-jwt/core`](https://www.npmjs.com/package/@sd-jwt/core), ES256 via WebCrypto** —
  runs in **Node.js and the browser**, no Node-only dependencies.

## 📖 Usage & API docs

**→ [`packages/verifiable-intent/README.md`](./packages/verifiable-intent/README.md)** — install,
Immediate + Autonomous walkthroughs, `verifyChain`, constraints, selective disclosure, multi-pair,
and the full API reference. Runnable examples live in
[`packages/verifiable-intent/examples/`](./packages/verifiable-intent/examples/).

## Modes

- **Immediate** — L1 → L2 (final values) → verify.
- **Autonomous** — L1 → L2 (constraints + agent delegation) → split L3a/L3b → the network verifies
  the payment chain + constraints, the merchant verifies the checkout chain, each over only the L2
  view it receives.

## Layout

```
packages/verifiable-intent/   the npm library  (SD-JWT via @sd-jwt/core, ES256 via WebCrypto)
apps/demo/                     Vite + React demo (in-browser Immediate + Autonomous flows)
```

## Development

```bash
pnpm install
pnpm test         # library test suite
pnpm build        # build the library (dual ESM/CJS + .d.ts)
pnpm dev          # start the React demo on http://localhost:5173
pnpm typecheck    # typecheck every package
```

## License

[Apache-2.0](./LICENSE), matching the upstream
[`agent-intent/verifiable-intent`](https://github.com/agent-intent/verifiable-intent) reference.
