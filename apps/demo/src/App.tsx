import { useState } from "react";
import {
  baseJwtOf,
  checkoutHash,
  CONSTRAINT_TYPE,
  generateViKeyPair,
  issueL1,
  issueL2Autonomous,
  issueL2Immediate,
  issueL3Checkout,
  issueL3Payment,
  parseLayer,
  presentL2ForMerchant,
  presentL2ForNetwork,
  resolveDisclosures,
  VI_VCT,
  verifyChain,
  type Item,
  type Merchant,
  type PaymentInstrument,
  type VerificationResult,
  type ViLayer,
} from "verifiable-intent";


const MERCHANTS: Merchant[] = [
  { id: "m1", name: "Tennis Warehouse", website: "https://tenniswarehouse.example" },
];
const ITEMS: Item[] = [{ id: "BAB86345", sku: "BAB86345", title: "Babolat Pure Drive" }];
const PI: PaymentInstrument = { type: "card", id: "pi-1", description: "Visa ****4242" };
const CART_JWT = "eyJhbGciOiJFUzI1NiJ9.tennis-cart.sig";

type Mode = "AUTONOMOUS" | "IMMEDIATE";

interface Result {
  mode: Mode;
  layers: { title: string; layer: ViLayer }[];
  views?: { merchant: Record<string, unknown>; network: Record<string, unknown> };
  verifications: { label: string; result: VerificationResult }[];
}

export function App() {
  const [mode, setMode] = useState<Mode>("AUTONOMOUS");
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(mode === "AUTONOMOUS" ? await runAutonomous() : await runImmediate());
    } catch (e) {
      setError(e instanceof Error ? `${e.message}\n${e.stack ?? ""}` : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app">
      <h1>Verifiable Intent</h1>
      <p className="subtitle">
        In-browser demo (ES256 / WebCrypto). SD-JWT mechanics via <code>@sd-jwt/core</code>; the VI
        delegation chain (L1→L2→L3), selective disclosure, and constraint checks on top.
      </p>

      <div className="toolbar">
        <div className="modes">
          {(["AUTONOMOUS", "IMMEDIATE"] as Mode[]).map((m) => (
            <button
              key={m}
              className={`mode ${mode === m ? "active" : ""}`}
              onClick={() => setMode(m)}
              disabled={busy}
            >
              {m === "AUTONOMOUS" ? "Autonomous (3-layer)" : "Immediate (2-layer)"}
            </button>
          ))}
        </div>
        <button onClick={run} disabled={busy}>
          {busy ? "Running…" : "Run flow"}
        </button>
      </div>

      {error && (
        <pre className="note" style={{ borderColor: "var(--bad)", color: "var(--bad)" }}>
          {error}
        </pre>
      )}

      {result && (
        <>
          <div className="layers">
            {result.verifications.map((v) => (
              <div className="layer" key={v.label}>
                <h3>
                  {v.label}
                  <span className={`badge ${v.result.valid ? "ok" : "bad"}`} style={{ marginLeft: 8 }}>
                    {v.result.valid ? "valid" : "invalid"}
                  </span>
                </h3>
                {v.result.errors.length > 0 && <pre>{v.result.errors.join("\n")}</pre>}
                <pre>
                  {[
                    `mode: ${v.result.mode ?? "-"}`,
                    `checks: ${v.result.checksPerformed.join(", ") || "-"}`,
                    v.result.checksSkipped.length ? `skipped: ${v.result.checksSkipped.join(", ")}` : "",
                  ]
                    .filter(Boolean)
                    .join("\n")}
                </pre>
              </div>
            ))}
          </div>

          {result.views && (
            <div className="layers">
              <div className="layer">
                <h3>
                  🛍️ Merchant sees <span className="typ">L2 checkout view</span>
                </h3>
                <p className="hint">Only the checkout mandate + selected item — no payment details.</p>
                <pre>{JSON.stringify(delegates(result.views.merchant), null, 2)}</pre>
              </div>
              <div className="layer">
                <h3>
                  🏦 Network sees <span className="typ">L2 payment view</span>
                </h3>
                <p className="hint">Only the payment mandate + selected merchant — no cart contents.</p>
                <pre>{JSON.stringify(delegates(result.views.network), null, 2)}</pre>
              </div>
            </div>
          )}

          <div className="layers">
            {result.layers.map((l) => (
              <div className="layer" key={l.title}>
                <h3>
                  {l.title}
                  <span className="typ">typ: {l.layer.header.typ}</span>
                </h3>
                <pre>{JSON.stringify(l.layer.payload, null, 2)}</pre>
                <pre>{l.layer.serialized}</pre>
              </div>
            ))}
          </div>
        </>
      )}

      <p className="note">
        Each layer is a plain RFC 9901 SD-JWT; layers are linked by <code>cnf</code> (key delegation)
        and <code>sd_hash</code> (byte binding), and mandates ride as array-element disclosures
        referenced from <code>delegate_payload</code>. The split L3 <code>sd_hash</code> binds each
        leg to only the L2 view its recipient receives.
      </p>
    </div>
  );
}

/** Show just the resolved mandate types a party can see (keeps the card readable). */
function delegates(claims: Record<string, unknown>): unknown {
  const d = Array.isArray(claims["delegate_payload"]) ? claims["delegate_payload"] : [];
  return d.map((m) => (m && typeof m === "object" ? { vct: (m as Record<string, unknown>)["vct"], ...(m as object) } : m));
}

async function runImmediate(): Promise<Result> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = await generateViKeyPair();
  const user = await generateViKeyPair();

  const l1 = await issueL1(
    {
      iss: "https://issuer.example",
      sub: "user-alice",
      vct: VI_VCT.L1_CARD,
      userPublicJwk: user.publicJwk,
      iat: now,
      exp: now + 86_400,
      visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
      email: "alice@example.com",
      issuerPrivateKey: issuer.privateKey,
      issuerKid: issuer.kid,
    },
  );

  const l2 = await issueL2Immediate(
    {
      l1,
      aud: "agent://shopping-bot",
      nonce: nonce(),
      iat: now,
      exp: now + 900,
      userPrivateKey: user.privateKey,
      userKid: user.kid,
      checkoutJwt: CART_JWT,
      payee: MERCHANTS[0]!,
      paymentAmount: { currency: "USD", amount: 4200 },
      paymentInstrument: PI,
    },
  );

  const result = await verifyChain(
    { l1, l2, resolveIssuerKey: async () => issuer.publicJwk, now },
  );

  return {
    mode: "IMMEDIATE",
    layers: [
      { title: "Layer 1 — issuer → user", layer: l1 },
      { title: "Layer 2 — user → agent (final values)", layer: l2 },
    ],
    verifications: [{ label: "Verification", result }],
  };
}

async function runAutonomous(): Promise<Result> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = await generateViKeyPair();
  const user = await generateViKeyPair();
  const agent = await generateViKeyPair();

  const l1 = await issueL1(
    {
      iss: "https://issuer.example",
      sub: "user-alice",
      vct: VI_VCT.L1_CARD,
      userPublicJwk: user.publicJwk,
      iat: now,
      exp: now + 86_400,
      visible: { pan_last_four: "4242", scheme: "Mastercard", card_id: "pi-1" },
      email: "alice@example.com",
      issuerPrivateKey: issuer.privateKey,
      issuerKid: issuer.kid,
    },
  );

  const l2 = await issueL2Autonomous(
    {
      l1,
      aud: "agent://shopping-bot",
      nonce: nonce(),
      iat: now,
      exp: now + 86_400,
      userPrivateKey: user.privateKey,
      userKid: user.kid,
      agentPublicJwk: agent.publicJwk,
      agentKid: agent.kid,
      promptSummary: "Buy a Babolat tennis racket under $400",
      merchants: MERCHANTS,
      acceptableItems: ITEMS,
      checkoutConstraints: [
        { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: MERCHANTS },
        { type: CONSTRAINT_TYPE.LINE_ITEMS, items: [{ id: "li-1", acceptable_items: ITEMS, quantity: 1 }] },
      ],
      paymentConstraints: [
        { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 },
        { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: MERCHANTS },
      ],
      paymentInstrument: PI,
    },
  );

  // Agent selects the product, gets a merchant checkout, and builds the split L3.
  const cHash = await checkoutHash(CART_JWT);
  const l2Base = baseJwtOf(l2.serialized);
  const netView = await presentL2ForNetwork(l2);
  const merView = await presentL2ForMerchant(l2);

  const l3a = await issueL3Payment(
    {
      nonce: nonce(),
      aud: "https://network.example",
      iat: now,
      exp: now + 300,
      agentPrivateKey: agent.privateKey,
      agentKid: agent.kid,
      l2BaseJwt: l2Base,
      transactionId: cHash,
      payee: MERCHANTS[0]!,
      paymentAmount: { currency: "USD", amount: 25000 },
      paymentInstrument: PI,
      finalMerchant: MERCHANTS[0]!,
      l2PaymentDisclosure: netView.disclosures[0],
      l2MerchantDisclosure: netView.disclosures[1],
    },
  );

  const l3b = await issueL3Checkout(
    {
      nonce: nonce(),
      aud: "https://tenniswarehouse.example",
      iat: now,
      exp: now + 300,
      agentPrivateKey: agent.privateKey,
      agentKid: agent.kid,
      l2BaseJwt: l2Base,
      checkoutJwt: CART_JWT,
      checkoutHash: cHash,
      l2CheckoutDisclosure: merView.disclosures[0],
      l2ItemDisclosure: merView.disclosures[1],
    },
  );

  const resolveIssuerKey = async () => issuer.publicJwk;
  const network = await verifyChain(
    { l1, l2, l3Payment: l3a, resolveIssuerKey, now, l2PaymentSerialized: netView.serialized },
  );
  const merchant = await verifyChain(
    { l1, l2, l3Checkout: l3b, resolveIssuerKey, now, l2CheckoutSerialized: merView.serialized },
  );

  // What each party actually receives, resolved.
  const merchantL2 = await parseLayer(merView.serialized);
  const networkL2 = await parseLayer(netView.serialized);

  return {
    mode: "AUTONOMOUS",
    layers: [
      { title: "Layer 1 — issuer → user", layer: l1 },
      { title: "Layer 2 — user → agent (constraints + delegation)", layer: l2 },
      { title: "Layer 3a — agent → network (payment)", layer: l3a },
      { title: "Layer 3b — agent → merchant (checkout)", layer: l3b },
    ],
    views: {
      merchant: await resolveDisclosures(merchantL2.payload, merchantL2.disclosureStrings),
      network: await resolveDisclosures(networkL2.payload, networkL2.disclosureStrings),
    },
    verifications: [
      { label: "🏦 Network — payment chain + constraints", result: network },
      { label: "🛍️ Merchant — checkout chain", result: merchant },
    ],
  };
}

function nonce(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
