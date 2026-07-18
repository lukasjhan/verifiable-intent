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
> Every layer is a **plain RFC 9901 SD-JWT** — VI does **not** concatenate layers with `~~`
> (that's an AP2/draft-gco thing). Key-binding claims live in each layer's payload; "key binding"
> means the layer is signed by the key named in the previous layer's `cnf`.

## Layout

```
packages/verifiable-intent/   the npm library  (SD-JWT via @sd-jwt/core, ES256 via WebCrypto)
apps/demo/                     Vite + React demo (in-browser Immediate + Autonomous flows)
```

## Getting started

```bash
pnpm install
pnpm test         # run the library test suite
pnpm build        # build the library (dual ESM/CJS + .d.ts)
pnpm dev          # start the React demo on http://localhost:5173
pnpm typecheck    # typecheck every package
```

## Status

Working end-to-end. Both flows issue, route selectively, and verify:

- **Immediate** — L1 → L2 (final values) → verify.
- **Autonomous** — L1 → L2 (constraints + agent delegation) → split L3a/L3b → the network verifies
  the payment chain + constraints, the merchant verifies the checkout chain, each over only the L2
  view it receives.

Selective disclosure (`delegate_payload` mandates + nested merchant/item refs), the split-L3
selective `sd_hash`, single-pair chain verification, and the constraint engine are implemented and
tested. Remaining `TODO`s: multi-mandate-pair L2 and network-side stateful constraint enforcement
(budget / recurrence).

## License

[Apache-2.0](./LICENSE), matching the upstream
[`agent-intent/verifiable-intent`](https://github.com/agent-intent/verifiable-intent) reference.
