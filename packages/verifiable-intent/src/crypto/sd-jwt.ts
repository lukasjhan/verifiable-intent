/**
 * SD-JWT issuance, serialization, and parsing — all via `@sd-jwt/core`.
 *
 * Two issuance paths, both library-native:
 *   - {@link sdjwtFor}(key).issue(payload, frame) — the high-level `SDJwtInstance` path, used for
 *     L1 and L3 where disclosures can be extracted declaratively from an inline payload.
 *   - {@link signSdJwt} — the `Jwt` + `SDJwt` container path, used for L2 where disclosures must be
 *     built explicitly (shared merchant/item disclosures + the staged `reference` self-hash), which
 *     no single declarative `pack()` pass can express.
 */
import { Jwt, SDJwt, SDJwtInstance, Disclosure, splitSdJwt } from "@sd-jwt/core";
import type { JoseHeader, ViLayer } from "../types.js";
import { hasher, hasherAndAlg, randomSalt, signerFor } from "./webcrypto.js";

/** An `SDJwtInstance` configured to sign with `privateKey` (ES256 / sha-256, VI sets `typ` itself). */
export function sdjwtFor(privateKey: unknown): SDJwtInstance<Record<string, unknown>> {
  return new SDJwtInstance<Record<string, unknown>>({
    signer: signerFor(privateKey as CryptoKey),
    signAlg: "ES256",
    hasher,
    hashAlg: "sha-256",
    saltGenerator: (length: number) => randomSalt(length),
    omitTyp: true, // VI provides its own layer-specific `typ` via the issue() header option.
  });
}

/**
 * Sign a pre-assembled payload and attach explicit disclosures, via core's `Jwt` + `SDJwt`.
 * Used by L2, whose disclosures are created outside `pack()` (shared + self-referential).
 */
export async function signSdJwt(
  header: JoseHeader,
  payload: Record<string, unknown>,
  disclosureStrings: readonly string[],
  privateKey: unknown,
): Promise<string> {
  const jwt = new Jwt({ header, payload });
  await jwt.sign(signerFor(privateKey as CryptoKey));
  const disclosures = await Promise.all(
    disclosureStrings.map((s) => Disclosure.fromEncode(s, hasherAndAlg)),
  );
  return new SDJwt({ jwt, disclosures }).encodeSDJwt();
}

/**
 * Serialize a selective presentation via core's `SDJwt` container: a base JWT re-serialized with a
 * chosen subset of disclosures. Byte-identical to the raw `~`-join (the base JWT and disclosure
 * strings round-trip through `Jwt`/`Disclosure` unchanged), so split-L3 `sd_hash` stays consistent.
 */
export async function encodePresentation(
  baseJwt: string,
  disclosureStrings: readonly string[],
): Promise<string> {
  const jwt = Jwt.fromEncode(baseJwt);
  const disclosures = await Promise.all(
    disclosureStrings.map((s) => Disclosure.fromEncode(s, hasherAndAlg)),
  );
  return new SDJwt({ jwt, disclosures }).encodeSDJwt();
}

/** The base JWT (first `~`-segment) of a serialized layer. */
export function baseJwtOf(serialized: string): string {
  return splitSdJwt(serialized).jwt;
}

/** Parse a compact SD-JWT string into a decoded {@link ViLayer}, keeping raw disclosure bytes. */
export async function parseLayer<P extends Record<string, unknown>>(
  serialized: string,
): Promise<ViLayer<P>> {
  const { jwt, disclosures: disclosureStrings } = splitSdJwt(serialized);
  const { header, payload } = Jwt.decodeJWT<JoseHeader, P>(jwt);
  const decoded = await Promise.all(
    disclosureStrings.map((s) => Disclosure.fromEncode(s, hasherAndAlg)),
  );
  return {
    serialized,
    header,
    payload,
    disclosureStrings,
    disclosures: decoded.map((d) => ({ salt: d.salt, key: d.key, value: d.value })),
  };
}

/** Verify a compact JWS signature only (no time-claim checks — VI checks expiry itself). */
export { verifySignature } from "./webcrypto.js";
