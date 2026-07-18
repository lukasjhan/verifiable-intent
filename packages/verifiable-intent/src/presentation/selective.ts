/**
 * Selective presentation (§4, §5.4).
 *
 * VI's privacy boundary: the merchant sees only the checkout leg, the network only the payment
 * leg. Because each layer is a plain SD-JWT, a "view" is the same base JWT re-serialized with a
 * SUBSET of its disclosures. A downstream layer's `sd_hash` is computed over exactly the view its
 * recipient will receive, so both sides hash identical bytes.
 */
import { VI_VCT } from "../constants.js";
import type { Disclosure, L2, ViLayer } from "../types.js";
import { baseJwtOf, encodePresentation } from "../crypto/sd-jwt.js";

export type DisclosurePredicate = (value: unknown, disclosure: Disclosure, index: number) => boolean;

export interface FoundDisclosure {
  index: number;
  /** The verbatim base64url disclosure string (for hashing / view-building). */
  encoded: string;
  value: unknown;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** True when a disclosure's value is a mandate with the given `vct`. */
function hasVct(value: unknown, vct: string): boolean {
  return isObj(value) && value["vct"] === vct;
}

/** Find the first disclosure whose decoded value matches `pred`. */
export function findDisclosure(layer: ViLayer, pred: DisclosurePredicate): FoundDisclosure | undefined {
  for (let i = 0; i < layer.disclosures.length; i++) {
    const d = layer.disclosures[i]!;
    if (pred(d.value, d, i)) return { index: i, encoded: layer.disclosureStrings[i]!, value: d.value };
  }
  return undefined;
}

/** All disclosures whose decoded value matches `pred`. */
export function findDisclosures(layer: ViLayer, pred: DisclosurePredicate): FoundDisclosure[] {
  const out: FoundDisclosure[] = [];
  for (let i = 0; i < layer.disclosures.length; i++) {
    const d = layer.disclosures[i]!;
    if (pred(d.value, d, i)) out.push({ index: i, encoded: layer.disclosureStrings[i]!, value: d.value });
  }
  return out;
}

/** Re-serialize a layer keeping only disclosures whose index is in `keep`. Base JWT is unchanged. */
export function present(layer: ViLayer, keep: ReadonlySet<number> | number[]): Promise<string> {
  const keepSet = keep instanceof Set ? keep : new Set(keep);
  const kept = layer.disclosureStrings.filter((_, i) => keepSet.has(i));
  return encodePresentation(baseJwtOf(layer.serialized), kept);
}

export interface RoleView {
  /** The `<base>~<disc>~<disc>~` presentation string (used for the L3 selective `sd_hash`). */
  serialized: string;
  /** The specific disclosure strings included, in the order used for `sd_hash`. */
  disclosures: [string, string];
}

/**
 * Network view of L2: `base + payment-mandate disclosure + selected-merchant disclosure`.
 * `merchant` selects which merchant disclosure to reveal (default: the first merchant).
 */
export function presentL2ForNetwork(l2: L2, merchant?: DisclosurePredicate): Promise<RoleView> {
  const payment =
    findDisclosure(l2, (v) => hasVct(v, VI_VCT.PAYMENT_OPEN) || hasVct(v, VI_VCT.PAYMENT_FINAL));
  const merchantDisc = findDisclosure(l2, merchant ?? isMerchant);
  if (!payment || !merchantDisc) throw new Error("L2 missing payment mandate or merchant disclosure");
  return view(l2, payment.encoded, merchantDisc.encoded);
}

/**
 * Merchant view of L2: `base + checkout-mandate disclosure + selected-item disclosure`.
 * `item` selects which item disclosure to reveal (default: the first item).
 */
export function presentL2ForMerchant(l2: L2, item?: DisclosurePredicate): Promise<RoleView> {
  const checkout =
    findDisclosure(l2, (v) => hasVct(v, VI_VCT.CHECKOUT_OPEN) || hasVct(v, VI_VCT.CHECKOUT_FINAL));
  const itemDisc = findDisclosure(l2, item ?? isItem);
  if (!checkout || !itemDisc) throw new Error("L2 missing checkout mandate or item disclosure");
  return view(l2, checkout.encoded, itemDisc.encoded);
}

async function view(l2: L2, a: string, b: string): Promise<RoleView> {
  return { serialized: await encodePresentation(baseJwtOf(l2.serialized), [a, b]), disclosures: [a, b] };
}

/** Heuristic: a merchant/payee disclosure has name/website but no `vct`. */
function isMerchant(v: unknown): boolean {
  return isObj(v) && !("vct" in v) && ("website" in v || "name" in v) && !("sku" in v);
}

/** Heuristic: an item disclosure has id/sku/title but no `vct`. */
function isItem(v: unknown): boolean {
  return isObj(v) && !("vct" in v) && ("sku" in v || "title" in v);
}
