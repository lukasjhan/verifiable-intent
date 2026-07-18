/**
 * Layer 1 issuance — issuer → user (§3.1).
 *
 * Uses `@sd-jwt/core`'s high-level `SDJwtInstance.issue()`: `email` is marked selectively
 * disclosable via a disclosure frame and the library packs it into `_sd`. Everything else
 * (iss, sub, iat, exp, vct, cnf, pan_last_four, scheme, card_id) stays visible.
 */
import { VI_TYP } from "../constants.js";
import type { Jwk, L1, L1Payload } from "../types.js";
import { parseLayer, sdjwtFor } from "../crypto/sd-jwt.js";

export interface IssueL1Params {
  iss: string;
  sub?: string;
  vct: string;
  aud?: string;
  /** The user's public key — becomes `cnf.jwk` (root of authority). */
  userPublicJwk: Jwk;
  iat: number;
  exp: number;
  /** Always-visible identity/card claims. */
  visible?: Partial<Pick<L1Payload, "pan_last_four" | "scheme" | "card_id">>;
  /** Selectively-disclosable email (packed into `_sd` by the library). */
  email?: string;
  /** Issuer signing key + its `kid` for JWKS discovery. */
  issuerPrivateKey: unknown;
  issuerKid: string;
}

/** Issue an L1 root credential. */
export async function issueL1(params: IssueL1Params): Promise<L1> {
  const payload: Record<string, unknown> = {
    iss: params.iss,
    ...(params.sub ? { sub: params.sub } : {}),
    iat: params.iat,
    exp: params.exp,
    vct: params.vct,
    ...(params.aud ? { aud: params.aud } : {}),
    cnf: { jwk: params.userPublicJwk },
    ...params.visible,
    ...(params.email !== undefined ? { email: params.email } : {}),
  };
  const frame = params.email !== undefined ? { _sd: ["email"] } : undefined;

  const encoded = await sdjwtFor(params.issuerPrivateKey).issue(payload, frame as never, {
    header: { alg: "ES256", typ: VI_TYP.L1, kid: params.issuerKid },
  });
  return parseLayer<L1Payload>(encoded);
}
