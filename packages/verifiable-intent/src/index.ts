/**
 * verifiable-intent — layered SD-JWT credentials for agentic commerce.
 *
 * Implements the Verifiable Intent (VI) v0.1-draft credential format:
 *   L1 (issuer → user) → L2 (user → agent) → L3 (agent → verifier, split L3a/L3b).
 *
 * All SD-JWT mechanics (disclosures, packing, serialization, signing) are delegated to
 * `@sd-jwt/core`; this package adds the VI delegation model on top: `cnf` key delegation,
 * `sd_hash` byte-linking, `delegate_payload` mandate references, and constraint verification.
 */

// Constants & types
export * from "./constants.js";
export * from "./types.js";

// Crypto
export { sha256, sdHash, checkoutHash } from "./crypto/hash.js";
export { generateViKeyPair, importPublicKey, jwkThumbprint, toCnf, type ViKeyPair } from "./crypto/keys.js";
export { randomSalt } from "./crypto/webcrypto.js";
export {
  createDisclosure,
  hashDisclosure,
  hashAll,
  createDelegateRef,
  delegateRefHash,
  resolveDisclosures,
  DELEGATE_REF_KEY,
  SD_ALG,
} from "./crypto/disclosure.js";
export {
  encodePresentation,
  parseLayer,
  baseJwtOf,
  sdjwtFor,
  signSdJwt,
} from "./crypto/sd-jwt.js";

// Issuance
export { issueL1, type IssueL1Params } from "./issuance/issuer.js";
export {
  issueL2Immediate,
  issueL2Autonomous,
  issueL2AutonomousMultiPair,
  type IssueL2ImmediateParams,
  type IssueL2AutonomousParams,
  type IssueL2AutonomousMultiParams,
  type AutonomousPair,
} from "./issuance/user.js";
export {
  issueL3Payment,
  issueL3Checkout,
  type IssueL3PaymentParams,
  type IssueL3CheckoutParams,
} from "./issuance/agent.js";

// Verification & constraints
export { verifyChain, type VerifyChainParams, type SplitL3 } from "./verification/chain.js";
export {
  checkConstraints,
  isKnownConstraint,
  type CheckConstraintsOptions,
} from "./constraints/index.js";

// Presentation
export {
  present,
  findDisclosure,
  findDisclosures,
  presentL2ForNetwork,
  presentL2ForMerchant,
  type DisclosurePredicate,
  type FoundDisclosure,
  type RoleView,
} from "./presentation/selective.js";
