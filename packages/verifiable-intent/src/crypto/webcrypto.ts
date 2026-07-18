/**
 * Raw crypto primitives via WebCrypto (isomorphic: Node 20+ and browsers). ES256 only.
 *
 * This is the ONLY place that touches signature/hash crypto. Everything SD-JWT-shaped
 * (disclosures, packing, serialization) goes through `@sd-jwt/core`; this module just provides
 * the `Signer` / `Hasher` / key material that core needs.
 */
import {
  base64UrlToUint8Array,
  uint8ArrayToBase64Url,
  type Hasher,
  type HasherAndAlg,
  type Signer,
} from "@sd-jwt/core";
import type { Jwk, Sd256Hash } from "../types.js";

const enc = new TextEncoder();
const ES256_PARAMS = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN_PARAMS = { name: "ECDSA", hash: { name: "SHA-256" } } as const;

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

async function digest(data: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/** B64U(SHA-256(input)). */
export async function sha256(input: string | Uint8Array): Promise<Sd256Hash> {
  return uint8ArrayToBase64Url(await digest(input));
}

/** The `@sd-jwt/core` Hasher: returns raw digest bytes (base64url-encoded by the caller). */
export const hasher: Hasher = async (data, _alg) => {
  const bytes = typeof data === "string" ? enc.encode(data) : new Uint8Array(data as ArrayBuffer);
  return digest(bytes);
};

/** `@sd-jwt/core` HasherAndAlg bundle used for disclosure digests. */
export const hasherAndAlg: HasherAndAlg = { hasher, alg: "sha-256" };

// ---------------------------------------------------------------------------
// Salt
// ---------------------------------------------------------------------------

/** base64url of `length` random bytes (default 16). */
export function randomSalt(length = 16): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return uint8ArrayToBase64Url(bytes);
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export interface ViKeyPair {
  /** Private CryptoKey — pass to `signerFor`. */
  privateKey: CryptoKey;
  /** Public JWK (with `kid` + `alg`), suitable for a `cnf` claim or JWKS. */
  publicJwk: Jwk;
  /** RFC 7638 thumbprint, used as a stable `kid`. */
  kid: string;
}

/** Generate a fresh ES256 (P-256) key pair with a thumbprint-derived `kid`. */
export async function generateViKeyPair(): Promise<ViKeyPair> {
  const pair = (await crypto.subtle.generateKey(ES256_PARAMS, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  const kid = await jwkThumbprint(raw);
  const publicJwk: Jwk = { kty: raw.kty!, crv: raw.crv!, x: raw.x!, y: raw.y!, kid, alg: "ES256" };
  return { privateKey: pair.privateKey, publicJwk, kid };
}

/** Import a public JWK for verification. */
export async function importPublicKey(jwk: Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, ES256_PARAMS, false, ["verify"]);
}

/** RFC 7638 JWK thumbprint (base64url of SHA-256 over the canonical member subset). */
export async function jwkThumbprint(jwk: JsonWebKey | Jwk): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return sha256(canonical);
}

// ---------------------------------------------------------------------------
// Sign / verify (ES256)
// ---------------------------------------------------------------------------

/** Build an `@sd-jwt/core` Signer bound to a private key (WebCrypto ECDSA P-256 → JWS r||s). */
export function signerFor(privateKey: CryptoKey): Signer {
  return async (data: string) => {
    const sig = await crypto.subtle.sign(SIGN_PARAMS, privateKey, enc.encode(data));
    return uint8ArrayToBase64Url(new Uint8Array(sig));
  };
}

/**
 * Verify a compact JWS signature ONLY (no time-claim checks — VI does expiry itself with an
 * injected clock). Returns false on any structural or signature failure.
 */
export async function verifySignature(compactJwt: string, publicJwk: Jwk): Promise<boolean> {
  try {
    const [h, p, s] = compactJwt.split(".");
    if (!h || !p || !s) return false;
    const key = await importPublicKey(publicJwk);
    const sig = base64UrlToUint8Array(s);
    return crypto.subtle.verify(SIGN_PARAMS, key, sig as BufferSource, enc.encode(`${h}.${p}`));
  } catch {
    return false;
  }
}
