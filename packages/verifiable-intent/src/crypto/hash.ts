/**
 * VI hash helpers, all `B64U(SHA-256(...))` via WebCrypto (see `./webcrypto.ts`).
 */
import type { Sd256Hash } from "../types.js";
import { sha256 } from "./webcrypto.js";

export { sha256 };

/**
 * sd_hash of a received layer (§6.1). Input MUST be the serialized SD-JWT exactly as received
 * (base JWT + `~` + each disclosure + trailing `~`) so both sides hash identical bytes.
 */
export function sdHash(serializedLayer: string): Promise<Sd256Hash> {
  return sha256(serializedLayer);
}

/** checkout_hash / transaction_id binding (§8): B64U(SHA-256(ASCII(checkout_jwt))). */
export function checkoutHash(checkoutJwt: string): Promise<Sd256Hash> {
  return sha256(checkoutJwt);
}
