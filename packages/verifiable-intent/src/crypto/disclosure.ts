/**
 * SD-JWT selective disclosure — thin VI-shaped wrappers over `@sd-jwt/core`.
 *
 * All disclosure encoding and digesting is delegated to `@sd-jwt/core` (`Disclosure`); this module
 * only adds VI conventions on top: array-element disclosures for mandates, referenced from a
 * `delegate_payload` claim as `{"...": <digest>}` (core's `SD_LIST_KEY`), plus a VI-specific
 * resolver (see {@link resolveDisclosures}).
 */
import { Disclosure, SD_LIST_KEY } from "@sd-jwt/core";
import type { Sd256Hash } from "../types.js";
import { hasherAndAlg, randomSalt } from "./webcrypto.js";

/** The array-element reference marker inside `delegate_payload` / nested constraint refs (`"..."`). */
export const DELEGATE_REF_KEY = SD_LIST_KEY;

/** SD-JWT digest algorithm identifier carried as the `_sd_alg` claim. */
export const SD_ALG = "sha-256";

/**
 * Create a disclosure string via `@sd-jwt/core`. Pass `key = null` for an array-element
 * disclosure (`[salt, value]`), or a claim name for an object-property one (`[salt, name, value]`).
 */
export function createDisclosure(key: string | null, value: unknown, salt: string = randomSalt()): string {
  const disc = key !== null ? new Disclosure([salt, key, value]) : new Disclosure([salt, value]);
  return disc.encode();
}

/** `base64url(SHA-256(ASCII(disclosure)))`, via core's `Disclosure.digest`. */
export async function hashDisclosure(disclosure: string): Promise<Sd256Hash> {
  const disc = await Disclosure.fromEncode(disclosure, hasherAndAlg);
  return disc.digest(hasherAndAlg);
}

/** Digest every disclosure, preserving order (the `_sd` / delegate hashing helper). */
export function hashAll(disclosures: readonly string[]): Promise<Sd256Hash[]> {
  return Promise.all(disclosures.map(hashDisclosure));
}

/** A `delegate_payload` / nested constraint reference: `{"...": digest}`. */
export function createDelegateRef(disclosureHash: Sd256Hash): { [SD_LIST_KEY]: Sd256Hash } {
  return { [DELEGATE_REF_KEY]: disclosureHash };
}

/** Read the digest out of a `{"...": digest}` reference, or `null` if it isn't one. */
export function delegateRefHash(value: unknown): Sd256Hash | null {
  if (value && typeof value === "object" && DELEGATE_REF_KEY in value) {
    const h = (value as Record<string, unknown>)[DELEGATE_REF_KEY];
    return typeof h === "string" ? h : null;
  }
  return null;
}

/**
 * Resolve disclosures into a full claim set. Object-property disclosures listed in `_sd` are
 * folded in by name; every `{"...": digest}` reference (in `delegate_payload` and nested inside
 * constraints) is recursively replaced by its disclosed value when present.
 *
 * This is VI's OWN resolver rather than core's `getClaims`/`unpack`, because VI's format is
 * deliberately non-standard: a single merchant/item disclosure is SHARED across constraints
 * (e.g. `allowed_merchants` and `allowed_payees`), so the same digest appears in multiple array
 * positions — which a strict RFC 9901 resolver rejects as a duplicate. Disclosure decoding and
 * digesting still go through core's `Disclosure`.
 */
export async function resolveDisclosures(
  payload: Record<string, unknown>,
  disclosureStrings: readonly string[],
): Promise<Record<string, unknown>> {
  const byDigest = new Map<Sd256Hash, { key?: string; value: unknown }>();
  for (const s of disclosureStrings) {
    const disc = await Disclosure.fromEncode(s, hasherAndAlg);
    byDigest.set(await disc.digest(hasherAndAlg), { key: disc.key, value: disc.value });
  }
  return resolveNode(payload, byDigest) as Record<string, unknown>;
}

function resolveNode(node: unknown, byDigest: Map<string, { key?: string; value: unknown }>): unknown {
  if (Array.isArray(node)) {
    return node.map((el) => {
      const h = delegateRefHash(el);
      const hit = h ? byDigest.get(h) : undefined;
      return hit ? resolveNode(hit.value, byDigest) : resolveNode(el, byDigest);
    });
  }
  if (node && typeof node === "object") {
    const src = node as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const sd = Array.isArray(src["_sd"]) ? (src["_sd"] as unknown[]) : [];
    const sdSet = new Set(sd.filter((x): x is string => typeof x === "string"));
    for (const [h, d] of byDigest) {
      if (sdSet.has(h) && d.key !== undefined) out[d.key] = resolveNode(d.value, byDigest);
    }
    for (const [k, v] of Object.entries(src)) {
      if (k === "_sd" || k === "_sd_alg") continue;
      out[k] = resolveNode(v, byDigest);
    }
    return out;
  }
  return node;
}
