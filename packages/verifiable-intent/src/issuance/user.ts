/**
 * Layer 2 issuance — user → agent (§3.1, §3.3).
 *
 * Reference: `issuance/user.py`.
 *   Immediate  → typ `kb-sd-jwt`,    two final-value mandates, no `cnf`.
 *   Autonomous → typ `kb-sd-jwt+kb`, open mandates with constraints + agent `cnf`, plus
 *                standalone merchant/item disclosures that the constraints reference by digest.
 *
 * In both modes the mandates are ARRAY-ELEMENT disclosures referenced from `delegate_payload`;
 * `_sd` carries every disclosure digest. The user's key (named by L1 `cnf.jwk`) signs.
 */
import { VI_TYP, VI_VCT, CONSTRAINT_TYPE } from "../constants.js";
import type {
  CheckoutMandateDict,
  Constraint,
  DelegateRef,
  Item,
  Jwk,
  JoseHeader,
  L1,
  L2,
  L2Payload,
  Merchant,
  Payee,
  PaymentAmount,
  PaymentInstrument,
  PaymentMandateDict,
} from "../types.js";
import { parseLayer, signSdJwt } from "../crypto/sd-jwt.js";
import {
  createDelegateRef,
  createDisclosure,
  hashAll,
  hashDisclosure,
  SD_ALG,
} from "../crypto/disclosure.js";
import { sdHash, checkoutHash } from "../crypto/hash.js";

interface CommonL2Params {
  l1: L1;
  aud: string;
  nonce: string;
  iat: number;
  exp?: number;
  iss?: string;
  /** User signing key = the private half of L1 `cnf.jwk`. */
  userPrivateKey: unknown;
  userKid?: string;
}

// ---------------------------------------------------------------------------
// Immediate mode
// ---------------------------------------------------------------------------

export interface IssueL2ImmediateParams extends CommonL2Params {
  /** Final merchant cart string; its SHA-256 becomes `checkout_hash`/`transaction_id`. */
  checkoutJwt: string;
  checkoutHash?: string;
  payee: Payee;
  paymentAmount: PaymentAmount;
  paymentInstrument?: PaymentInstrument;
  transactionId?: string;
}

export async function issueL2Immediate(params: IssueL2ImmediateParams): Promise<L2> {
  const cHash = params.checkoutHash ?? (await checkoutHash(params.checkoutJwt));

  const checkoutDict: CheckoutMandateDict = {
    vct: VI_VCT.CHECKOUT_FINAL,
    checkout_jwt: params.checkoutJwt,
    checkout_hash: cHash,
  };
  const paymentDict: PaymentMandateDict = {
    vct: VI_VCT.PAYMENT_FINAL,
    ...(params.paymentInstrument ? { payment_instrument: params.paymentInstrument } : {}),
    payee: params.payee,
    payment_amount: params.paymentAmount,
    transaction_id: params.transactionId ?? cHash,
  };

  const checkoutDisc = createDisclosure(null, checkoutDict);
  const paymentDisc = createDisclosure(null, paymentDict);
  const disclosures = [checkoutDisc, paymentDisc];

  return finishL2(params, disclosures, disclosures, VI_TYP.KB_SD_JWT);
}

// ---------------------------------------------------------------------------
// Autonomous mode
// ---------------------------------------------------------------------------

/** One checkout+payment mandate pair within an Autonomous L2. */
export interface AutonomousPair {
  /** Checkout constraints with inline merchant/item objects (rewritten to digest refs). */
  checkoutConstraints: Constraint[];
  /** Payment constraints with inline merchant objects in `allowed_payees.allowed`. */
  paymentConstraints: Constraint[];
  paymentInstrument: PaymentInstrument;
  riskData?: Record<string, unknown>;
}

interface AutonomousCommon extends CommonL2Params {
  /** Agent public key delegated to sign L3 (embedded as each mandate's `cnf`). */
  agentPublicJwk: Jwk;
  agentKid?: string;
  promptSummary?: string;
  /** Shared standalone merchant disclosures (constraints reference these by digest). */
  merchants: Merchant[];
  /** Shared standalone acceptable-item disclosures. */
  acceptableItems: Item[];
}

/** Single-pair Autonomous L2 (the common case). */
export interface IssueL2AutonomousParams extends AutonomousCommon, AutonomousPair {}

/** Multi-pair Autonomous L2: one L2 authorizing several checkout+payment pairs. */
export interface IssueL2AutonomousMultiParams extends AutonomousCommon {
  pairs: AutonomousPair[];
}

/** Issue an Autonomous L2 authorizing multiple mandate pairs against a shared merchant/item pool. */
export async function issueL2AutonomousMultiPair(params: IssueL2AutonomousMultiParams): Promise<L2> {
  // Shared standalone merchant + item disclosures (referenced by every pair's constraints).
  const merchantDiscs = params.merchants.map((m) => createDisclosure(null, m));
  const itemDiscs = params.acceptableItems.map((i) => createDisclosure(null, i));
  const merchantHashes = await hashAll(merchantDiscs);
  const itemHashes = await hashAll(itemDiscs);

  const agentJwk: Jwk = { ...params.agentPublicJwk };
  if (params.agentKid) agentJwk.kid = params.agentKid;
  const cnf = { jwk: agentJwk };

  const pairDiscs: string[] = []; // flat: checkout0, payment0, checkout1, payment1, ...
  for (const pair of params.pairs) {
    // Checkout mandate — rewrite merchant/item allowlists to digest refs.
    const checkoutConstraints = rewriteConstraints(pair.checkoutConstraints, (c) => {
      if (c.type === CONSTRAINT_TYPE.ALLOWED_MERCHANTS) {
        c["allowed"] = matchMerchantRefs(asArray(c["allowed"]), params.merchants, merchantHashes);
      } else if (c.type === CONSTRAINT_TYPE.LINE_ITEMS) {
        for (const entry of asArray(c["items"]) as Record<string, unknown>[]) {
          entry["acceptable_items"] = matchItemRefs(asArray(entry["acceptable_items"]), params.acceptableItems, itemHashes);
        }
      }
    });
    const checkoutDict: CheckoutMandateDict = { vct: VI_VCT.CHECKOUT_OPEN, cnf, constraints: checkoutConstraints };
    const checkoutDisc = createDisclosure(null, checkoutDict);
    const checkoutDiscHash = await hashDisclosure(checkoutDisc);

    // Payment mandate — rewrite payee allowlist, inject reference constraint binding this checkout.
    const paymentConstraints = rewriteConstraints(pair.paymentConstraints, (c) => {
      if (c.type === CONSTRAINT_TYPE.ALLOWED_PAYEES) {
        c["allowed"] = matchMerchantRefs(asArray(c["allowed"]), params.merchants, merchantHashes);
      }
    });
    paymentConstraints.push({ type: CONSTRAINT_TYPE.REFERENCE, conditional_transaction_id: checkoutDiscHash });
    const paymentDict: PaymentMandateDict = {
      vct: VI_VCT.PAYMENT_OPEN,
      cnf,
      payment_instrument: pair.paymentInstrument,
      ...(pair.riskData ? { risk_data: pair.riskData } : {}),
      constraints: paymentConstraints,
    };
    const paymentDisc = createDisclosure(null, paymentDict);
    pairDiscs.push(checkoutDisc, paymentDisc);
  }

  // Disclosure order matches the reference: merchants, items, then each pair's checkout+payment.
  const disclosures = [...merchantDiscs, ...itemDiscs, ...pairDiscs];
  return finishL2(params, disclosures, pairDiscs, VI_TYP.KB_SD_JWT_KB, params.promptSummary);
}

/** Single-pair Autonomous L2 (thin wrapper over {@link issueL2AutonomousMultiPair}). */
export async function issueL2Autonomous(params: IssueL2AutonomousParams): Promise<L2> {
  const { checkoutConstraints, paymentConstraints, paymentInstrument, riskData, ...common } = params;
  return issueL2AutonomousMultiPair({
    ...common,
    pairs: [{ checkoutConstraints, paymentConstraints, paymentInstrument, riskData }],
  });
}

// ---------------------------------------------------------------------------
// Shared assembly
// ---------------------------------------------------------------------------

async function finishL2(
  params: CommonL2Params,
  allDisclosures: string[],
  mandateDiscs: string[],
  typ: typeof VI_TYP.KB_SD_JWT | typeof VI_TYP.KB_SD_JWT_KB,
  promptSummary?: string,
): Promise<L2> {
  const delegate_payload: DelegateRef[] = [];
  for (const d of mandateDiscs) delegate_payload.push(createDelegateRef(await hashDisclosure(d)));

  // No `_sd`: all L2 disclosures are array-element (mandates/merchants/items), referenced from
  // `delegate_payload` and nested constraint refs. Only OBJECT-property disclosures belong in
  // `_sd` (VI L2 has none), keeping each digest unique per RFC 9901.
  const payload: L2Payload = {
    nonce: params.nonce,
    aud: params.aud,
    iat: params.iat,
    sd_hash: await sdHash(params.l1.serialized),
    delegate_payload,
    _sd_alg: SD_ALG,
    ...(promptSummary ? { prompt_summary: promptSummary } : {}),
    ...(params.iss ? { iss: params.iss } : {}),
    ...(params.exp !== undefined ? { exp: params.exp } : {}),
  };

  // Disclosures are built explicitly (shared merchant/item + staged reference), so sign + serialize
  // go through core's Jwt + SDJwt container rather than the declarative issue()/pack() path.
  const header: JoseHeader = { alg: "ES256", typ, kid: params.userKid };
  const encoded = await signSdJwt(header, payload, allDisclosures, params.userPrivateKey);
  return parseLayer<L2Payload>(encoded);
}

// ---------------------------------------------------------------------------
// Constraint reference matching (reference: _match_merchant_refs / _match_item_refs)
// ---------------------------------------------------------------------------

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

/** Deep-clone constraints (so we never mutate caller input) then apply `rewrite` to each. */
function rewriteConstraints(
  constraints: readonly Constraint[],
  rewrite: (c: Record<string, unknown>) => void,
): Constraint[] {
  const cloned = JSON.parse(JSON.stringify(constraints)) as Record<string, unknown>[];
  for (const c of cloned) rewrite(c);
  return cloned as Constraint[];
}

/** Replace inline merchant objects with `{"...": digest}` refs, matched by id then name. */
function matchMerchantRefs(
  originals: unknown[],
  merchants: Merchant[],
  hashes: string[],
): DelegateRef[] {
  const refs: DelegateRef[] = [];
  for (const orig of originals as Merchant[]) {
    if (!orig || (!orig.id && !orig.name)) throw new Error("Constraint merchant missing both id and name");
    const idx = merchants.findIndex((m) =>
      orig.id && m.id ? m.id === orig.id : !!orig.name && m.name === orig.name,
    );
    if (idx < 0) throw new Error(`Constraint references unknown merchant: ${orig.id ?? orig.name}`);
    refs.push(createDelegateRef(hashes[idx]!));
  }
  return refs;
}

/** Replace inline item objects with `{"...": digest}` refs, matched by id/sku intersection. */
function matchItemRefs(originals: unknown[], items: Item[], hashes: string[]): DelegateRef[] {
  const refs: DelegateRef[] = [];
  for (const orig of originals as Item[]) {
    const origKeys = new Set([orig?.id, orig?.sku].filter(Boolean));
    const idx = items.findIndex((it) => {
      const itemKeys = new Set([it.id, it.sku].filter(Boolean));
      return [...origKeys].some((k) => itemKeys.has(k as string));
    });
    if (idx < 0) throw new Error(`Constraint references unknown item: ${orig?.id ?? orig?.sku}`);
    refs.push(createDelegateRef(hashes[idx]!));
  }
  return refs;
}
