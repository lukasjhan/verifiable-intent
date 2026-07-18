/**
 * Layer 3 issuance — agent → verifier (Autonomous only, §3.1, §4).
 *
 * Uses `@sd-jwt/core`'s `SDJwtInstance.issue()`: the final mandate(s) sit inline in
 * `delegate_payload` and a disclosure frame packs them into array-element disclosures. L3 is split
 * into L3a (payment → network) and L3b (checkout → merchant); the agent key (named by the L2
 * mandate `cnf`) signs both, typ `kb-sd-jwt`, and neither carries `cnf` (terminal delegation).
 *
 * Each leg's `sd_hash` is SELECTIVE: it hashes only the L2 view that leg is entitled to see
 * (L2 base JWT + that leg's L2 disclosures), computed before issue() and carried as a claim.
 */
import { VI_TYP, VI_VCT } from "../constants.js";
import type {
  FinalCheckoutMandateDict,
  FinalPaymentMandateDict,
  L3Checkout,
  L3Payment,
  L3Payload,
  Merchant,
  Payee,
  PaymentAmount,
  PaymentInstrument,
} from "../types.js";
import { encodePresentation, parseLayer, sdjwtFor } from "../crypto/sd-jwt.js";
import { sha256 } from "../crypto/hash.js";

interface CommonL3Params {
  nonce: string;
  aud: string;
  iat: number;
  exp?: number;
  iss?: string;
  /** Agent signing key = the private half of the L2 mandate `cnf.jwk`. */
  agentPrivateKey: unknown;
  /** MUST match the `kid` inside the L2 mandate `cnf.jwk` (§10.4). */
  agentKid: string;
  /** The L2 base JWT (`baseJwtOf(l2.serialized)`). */
  l2BaseJwt: string;
}

export interface IssueL3PaymentParams extends CommonL3Params {
  transactionId: string;
  payee: Payee;
  paymentAmount: PaymentAmount;
  paymentInstrument: PaymentInstrument;
  /** Selected merchant (becomes L3a's own standalone disclosure). */
  finalMerchant: Merchant;
  /** L2 payment mandate disclosure (b64) — part of the network's L2 view for `sd_hash`. */
  l2PaymentDisclosure: string;
  /** Selected L2 merchant disclosure (b64) — the other part of the network's L2 view. */
  l2MerchantDisclosure: string;
}

export interface IssueL3CheckoutParams extends CommonL3Params {
  checkoutJwt: string;
  checkoutHash: string;
  /** L2 checkout mandate disclosure (b64) — part of the merchant's L2 view for `sd_hash`. */
  l2CheckoutDisclosure: string;
  /** Selected L2 item disclosure (b64) — the other part of the merchant's L2 view. */
  l2ItemDisclosure: string;
}

/** L3a — payment leg presented to the network. */
export async function issueL3Payment(params: IssueL3PaymentParams): Promise<L3Payment> {
  const finalPayment: FinalPaymentMandateDict = {
    vct: VI_VCT.PAYMENT_FINAL,
    transaction_id: params.transactionId,
    payee: params.payee,
    payment_amount: params.paymentAmount,
    payment_instrument: params.paymentInstrument,
  };
  // sd_hash binds to the network's L2 view: base + payment disclosure + merchant disclosure.
  const sd_hash = await sha256(
    await encodePresentation(params.l2BaseJwt, [params.l2PaymentDisclosure, params.l2MerchantDisclosure]),
  );
  return finishL3(params, sd_hash, [params.finalMerchant, finalPayment]);
}

/** L3b — checkout leg presented to the merchant. */
export async function issueL3Checkout(params: IssueL3CheckoutParams): Promise<L3Checkout> {
  const finalCheckout: FinalCheckoutMandateDict = {
    vct: VI_VCT.CHECKOUT_FINAL,
    checkout_jwt: params.checkoutJwt,
    checkout_hash: params.checkoutHash,
  };
  // sd_hash binds to the merchant's L2 view: base + checkout disclosure + item disclosure.
  const sd_hash = await sha256(
    await encodePresentation(params.l2BaseJwt, [params.l2CheckoutDisclosure, params.l2ItemDisclosure]),
  );
  return finishL3(params, sd_hash, [finalCheckout]);
}

async function finishL3(
  params: CommonL3Params,
  sd_hash: string,
  mandates: Record<string, unknown>[],
): Promise<L3Payment> {
  const payload: Record<string, unknown> = {
    nonce: params.nonce,
    aud: params.aud,
    sd_hash,
    iat: params.iat,
    delegate_payload: mandates,
    ...(params.iss ? { iss: params.iss } : {}),
    ...(params.exp !== undefined ? { exp: params.exp } : {}),
  };
  // Pack each delegate_payload element into an array-element disclosure.
  const frame = { delegate_payload: { _sd: mandates.map((_, i) => i) } };

  const encoded = await sdjwtFor(params.agentPrivateKey).issue(payload, frame as never, {
    header: { alg: "ES256", typ: VI_TYP.KB_SD_JWT, kid: params.agentKid },
  });
  return parseLayer<L3Payload>(encoded);
}
