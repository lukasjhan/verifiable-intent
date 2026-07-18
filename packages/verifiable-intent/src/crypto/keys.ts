/**
 * ES256 (P-256) key helpers. Implementation lives in `./webcrypto.ts`; this module re-exports
 * the key surface and adds the `cnf` helper.
 */
import type { Cnf, Jwk } from "../types.js";

export { generateViKeyPair, importPublicKey, jwkThumbprint, type ViKeyPair } from "./webcrypto.js";

/** Build a `cnf` claim naming the key permitted to sign the next layer (RFC 7800). */
export function toCnf(publicJwk: Jwk): Cnf {
  return publicJwk.kid ? { jwk: publicJwk, kid: publicJwk.kid } : { jwk: publicJwk };
}
