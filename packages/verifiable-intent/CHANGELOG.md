# Changelog

The library version tracks the [Verifiable Intent spec](https://github.com/agent-intent/verifiable-intent)
version it implements — see [Versioning](./README.md#versioning).

## 0.1.0

Initial release. Implements the Verifiable Intent (VI) **`v0.1-draft`** credential format.

- L1 / L2 / L3 issuance — Immediate (2-layer) and Autonomous (3-layer, agent delegation) modes.
- Selective disclosure — `delegate_payload` mandates + nested merchant/item references, and
  per-recipient L2 views (merchant vs network).
- Split-L3 selective `sd_hash` binding each leg to only the L2 view its recipient receives.
- Multi-mandate-pair chain verification with mandate-smuggling and orphan detection, and a
  `card_id` ↔ `payment_instrument` cross-check.
- Constraint engine — eight constraint types, PERMISSIVE/STRICT modes, and `line_items`
  `match_mode` (minimum/exact) with per-id quantity caps.
- Built on `@sd-jwt/core`; ES256 via WebCrypto; runs in Node.js and the browser; ESM + CJS.
