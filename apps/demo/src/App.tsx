import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight, Check, ChevronLeft, ChevronRight, ExternalLink, Eye, EyeOff, Layers, Moon, ShieldCheck,
  ShieldX, Sun, Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LayerCard, type Highlight } from "@/components/LayerCard";
import { FlowBoard } from "@/components/FlowBoard";
import { cn } from "@/lib/utils";
import { ACTOR_META, SCENARIOS, type Actor, type Built, type ScenarioDef, type StepMeta } from "@/scenarios";

const short = (s: string, head = 10, tail = 6) => (s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s);

export function App() {
  const [dark, setDark] = useState(true);
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0]!.id);
  const [built, setBuilt] = useState<Built | null>(null);
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scenario = useMemo(() => SCENARIOS.find((s) => s.id === scenarioId)!, [scenarioId]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setBuilt(null);
    setStep(0);
    scenario
      .build()
      .then((b) => !cancelled && setBuilt(b))
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [scenario]);

  const steps = scenario.steps;
  const stepIdx = Math.min(step, steps.length - 1); // clamp: scenarios differ in length
  const current = steps[stepIdx]!;
  const activeActors = new Set<Actor>([
    current.actor as Actor,
    ...(current.transfer ? [current.transfer.to] : []),
    ...(current.active ?? []),
  ]);

  return (
    <div className="mx-auto min-h-screen max-w-6xl px-4 py-6 sm:px-5 sm:py-8">
      <Header dark={dark} onToggle={() => setDark((d) => !d)} />

      {/* Scenario picker — two rows */}
      <Tabs value={scenarioId} onValueChange={(id) => { setScenarioId(id); setStep(0); }} className="mt-6">
        <TabsList className="grid h-auto w-full grid-cols-2 gap-1 sm:grid-cols-3">
          {SCENARIOS.map((s) => (
            <TabsTrigger key={s.id} value={s.id} className="h-auto min-w-0 flex-col items-start gap-0.5 py-2 whitespace-normal">
              <span className="flex w-full items-center gap-1.5 text-xs font-semibold sm:text-sm">
                <span className="shrink-0">{s.icon}</span> <span className="truncate">{s.title}</span>
              </span>
              <span className="text-muted-foreground w-full truncate text-left text-[10px] font-normal">{s.tagline}</span>
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {error && (
        <Alert variant="destructive" className="mt-6">
          <ShieldX />
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {loading && (
        <div className="text-muted-foreground mt-16 flex items-center justify-center gap-2 text-sm">
          <Loader2 className="size-4 animate-spin" /> Running the flow in your browser (ES256 / WebCrypto)…
        </div>
      )}

      {built && !loading && (
        <div className="mt-6 grid gap-6 lg:grid-cols-[220px_1fr]">
          {/* Stepper rail */}
          <StepRail steps={steps} current={stepIdx} outcome={scenario.outcome} onJump={setStep} />

          {/* Main panel */}
          <div className="min-w-0 space-y-5">
            <FlowBoard
              stepId={current.id}
              built={built}
              active={activeActors}
              results={current.id === "verify" ? { network: built.networkResult?.valid, merchant: built.merchantResult?.valid } : undefined}
            />

            <div>
              <div className="mb-1 flex items-center gap-2">
                <span className="text-muted-foreground text-xs font-medium">
                  Step {stepIdx + 1} / {steps.length}
                </span>
                {current.transfer && (
                  <TransferPill from={current.transfer.from} to={current.transfer.to} what={current.transfer.what} />
                )}
              </div>
              <h2 className="text-xl font-semibold tracking-tight">{current.title}</h2>
              <p className="text-muted-foreground mt-1.5 max-w-2xl text-sm leading-relaxed">{current.situation}</p>
            </div>

            <Artifact step={current} built={built} scenario={scenario} />

            {/* Nav */}
            <div className="flex items-center justify-between pt-2">
              <Button variant="outline" size="sm" disabled={stepIdx === 0} onClick={() => setStep(Math.max(0, stepIdx - 1))}>
                <ChevronLeft /> Back
              </Button>
              {stepIdx < steps.length - 1 ? (
                <Button size="sm" onClick={() => setStep(Math.min(steps.length - 1, stepIdx + 1))}>
                  Next <ChevronRight />
                </Button>
              ) : (
                <Button size="sm" variant="secondary" onClick={() => setStep(0)}>
                  Restart
                </Button>
              )}
            </div>
          </div>
        </div>
      )}

      <Footer />
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function Header({ dark, onToggle }: { dark: boolean; onToggle: () => void }) {
  return (
    <header className="flex items-start justify-between gap-4">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight">Verifiable Intent</h1>
          <Badge variant="secondary" className="font-mono">v0.1</Badge>
        </div>
        <p className="text-muted-foreground mt-1 max-w-2xl text-sm">
          A guided walkthrough: how an AI agent proves a purchase was within the user's intent — and how
          verifiers catch it when it isn't. Everything runs in your browser with real ES256 signatures.
        </p>
      </div>
      <Button variant="outline" size="icon" onClick={onToggle} aria-label="Toggle theme">
        {dark ? <Sun /> : <Moon />}
      </Button>
    </header>
  );
}

function StepRail({ steps, current, outcome, onJump }: { steps: StepMeta[]; current: number; outcome: string; onJump: (i: number) => void }) {
  return (
    <ol className="flex gap-2 overflow-x-auto lg:sticky lg:top-6 lg:h-fit lg:flex-col lg:gap-0">
      {steps.map((s, i) => {
        const done = i < current;
        const active = i === current;
        const isVerify = s.id === "verify";
        return (
          <li key={s.id} className="shrink-0 lg:w-full">
            <button
              onClick={() => onJump(i)}
              className={cn(
                "flex w-full items-center gap-2.5 rounded-md px-2 py-2 text-left transition-colors",
                active ? "bg-accent" : "hover:bg-accent/50",
              )}
            >
              <span
                className={cn(
                  "flex size-6 shrink-0 items-center justify-center rounded-full border text-xs font-semibold",
                  active && "border-primary bg-primary text-primary-foreground",
                  done && "border-success bg-success/15 text-success",
                  !active && !done && "text-muted-foreground",
                )}
              >
                {done ? <Check className="size-3.5" /> : i + 1}
              </span>
              <span className={cn("hidden truncate text-xs lg:inline", active ? "font-medium" : "text-muted-foreground")}>
                {isVerify && outcome === "blocked" ? "Verify → blocked" : s.title}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function TransferPill({ from, to, what }: { from: Actor; to: Actor; what: string }) {
  return (
    <span className="text-muted-foreground inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-[11px]">
      {ACTOR_META[from].icon}
      <ArrowRight className="size-3" />
      {ACTOR_META[to].icon}
      <span className="ml-0.5">{what}</span>
    </span>
  );
}

/* --- per-step artifacts --------------------------------------------------- */

function Artifact({ step, built, scenario }: { step: StepMeta; built: Built; scenario: ScenarioDef }) {
  switch (step.id) {
    case "setup":
      return <SetupCard scenario={scenario} />;
    case "l1":
      return (
        <LayerCard
          title="Layer 1 — Issuer credential"
          subtitle="Signed by the bank; binds Alice's card to her key via cnf. Root of the chain."
          layer={built.l1}
          highlights={[
            { label: "iss", value: String(built.l1.payload.iss), note: "Who issued it. Verifiers fetch this issuer's public key to check the signature." },
            { label: "cnf.jwk", value: `Alice's key · ${short(built.kids.user)}`, mono: true, note: "Binds the credential to Alice's key — only she can sign the next layer (this is the delegation root)." },
            { label: "pan_last_four", value: `•••• ${String((built.l1.payload as any).pan_last_four ?? "")} · ${String((built.l1.payload as any).scheme ?? "")}`, note: "The card this represents. `email` is a selective disclosure — shown only if needed." },
          ]}
        />
      );
    case "l2":
      return <L2Artifact built={built} />;
    case "l3":
      return <L3Artifact built={built} />;
    case "route":
      return <RouteArtifact built={built} />;
    case "verify":
      return <VerifyArtifact built={built} scenario={scenario} />;
  }
}

function L3Artifact({ built }: { built: Built }) {
  const [rawOpen, setRawOpen] = useState(false);
  const amount = built.payment?.amount ?? "—";
  const payee = built.payment?.payee ?? "—";
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {built.l3a && (
        <LayerCard
          title="Layer 3a — Payment proof"
          subtitle="For the payment network. Signed by the agent's delegated key. Terminal (no cnf)."
          layer={built.l3a}
          rawOpen={rawOpen}
          onRawOpenChange={setRawOpen}
          highlights={[
            { label: "aud", value: "payment network", note: "Who receives this leg." },
            { label: "payment_amount", value: amount, note: "The actual charge — the network checks it against Alice's amount_range constraint." },
            { label: "payee", value: payee, note: "Where the money goes — checked against allowed_payees." },
            { label: "sd_hash", value: short(String(built.l3a.payload.sd_hash)), mono: true, note: "Binds to the network's L2 view (payment + merchant only) — proves the agent saw exactly that mandate." },
            { label: "header.kid", value: short(String(built.l3a.header.kid)), mono: true, note: "Names the signing key. The verifier resolves the real key from Alice's L2 cnf — it never trusts this header." },
          ]}
        />
      )}
      {built.l3b && (
        <LayerCard
          title="Layer 3b — Checkout proof"
          subtitle="For the merchant. Same agent key, bound to a different L2 view."
          layer={built.l3b}
          rawOpen={rawOpen}
          onRawOpenChange={setRawOpen}
          highlights={[
            { label: "aud", value: "the merchant", note: "Who receives this leg." },
            { label: "checkout_hash", value: "= L3a transaction_id", note: "Cross-links the two legs to the same transaction (dispute resolution can match them)." },
            { label: "sd_hash", value: short(String(built.l3b.payload.sd_hash)), mono: true, note: "Binds to the merchant's L2 view (checkout + item only) — a different view than L3a's." },
            { label: "header.kid", value: short(String(built.l3b.header.kid)), mono: true, note: "Same agent key, again resolved from L2 rather than trusted from here." },
          ]}
        />
      )}
    </div>
  );
}

function SetupCard({ scenario }: { scenario: ScenarioDef }) {
  return (
    <Card>
      <CardContent className="space-y-3 pt-6">
        <dl className="grid gap-2 text-sm">
          {scenario.facts.map((f) => (
            <div key={f.label} className="grid grid-cols-[110px_1fr] items-baseline gap-2">
              <dt className="text-muted-foreground text-xs uppercase tracking-wide">{f.label}</dt>
              <dd className="font-medium">{f.value}</dd>
            </div>
          ))}
        </dl>
        <Separator />
        <p className="text-muted-foreground text-xs">
          Five parties are involved. Watch the bar above: it highlights who is acting and where the data flows at
          each step.
        </p>
      </CardContent>
    </Card>
  );
}

function L2Artifact({ built }: { built: Built }) {
  const autonomous = built.mode === "AUTONOMOUS";
  const multi = (built.pairCount ?? 1) > 1;
  const highlights: Highlight[] = autonomous
    ? [
        { label: "aud", value: "the AI agent", note: "Who this mandate is delegated to." },
        { label: "mandate.cnf", value: `agent key · ${short(built.kids.agent ?? "")}`, mono: true, note: "Embeds the agent's key inside each mandate — only that key can produce a valid L3." },
        { label: "constraints", value: built.limits?.cap ?? "—", note: `Machine-checkable limits (from ${built.limits?.merchant ?? "approved stores"}). Verifiers re-derive them from this signed L2 — the agent can't loosen them.` },
        { label: "sd_hash", value: short(String(built.l2.payload.sd_hash)), mono: true, note: "SHA-256 of the exact L1 — pins this mandate to Alice's credential." },
      ]
    : [
        { label: "payment_amount", value: built.payment?.amount ?? "—", note: "The exact amount Alice approved. No range, no delegation — she decided." },
        { label: "checkout_hash", value: "= transaction_id", note: "Cart and payment are cross-linked so the amount can't be swapped for a different cart." },
        { label: "sd_hash", value: short(String(built.l2.payload.sd_hash)), mono: true, note: "Binds to the exact L1 credential." },
      ];
  return (
    <div className="space-y-3">
      {autonomous && (
        <div className="flex flex-wrap gap-1.5">
          {multi ? (
            <>
              <Badge variant="outline">🎾 pair 0 · racket ≤ $400</Badge>
              <Badge variant="outline">🧵 pair 1 · strings ≤ $30/mo</Badge>
            </>
          ) : (
            <>
              <Badge variant="outline">≤ $400 per transaction</Badge>
              <Badge variant="outline">1 racket max</Badge>
              <Badge variant="outline">approved merchants only</Badge>
            </>
          )}
          <Badge variant="muted">enforced cryptographically</Badge>
        </div>
      )}
      <LayerCard
        title={`Layer 2 — User mandate (${autonomous ? "Autonomous" : "Immediate"})${multi ? " · 2 pairs" : ""}`}
        subtitle={
          autonomous
            ? "Alice authorizes the agent within constraints. The agent's key is embedded so only it can act."
            : "Alice signs the exact cart + amount. No delegation, no constraints."
        }
        layer={built.l2}
        highlights={highlights}
      />
    </div>
  );
}

function RouteArtifact({ built }: { built: Built }) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <ViewColumn
          icon="🛍️"
          title="Merchant receives"
          sees={["The cart / line items", "Which store", "That a valid mandate exists"]}
          hidden={["Card number", "Payment amount", "Payment network details"]}
          mandates={built.merchantSees ?? []}
          bundle={[
            { label: "L1", jwt: built.l1.serialized },
            { label: "L2 · checkout view", jwt: built.merchantView?.serialized ?? "" },
            { label: "L3b", jwt: built.l3b?.serialized ?? "" },
          ]}
        />
        <ViewColumn
          icon="💳"
          title="Payment network receives"
          sees={["The amount + payee", "The spending constraints", "That a valid mandate exists"]}
          hidden={["Cart contents", "What was bought"]}
          mandates={built.networkSees ?? []}
          bundle={[
            { label: "L1", jwt: built.l1.serialized },
            { label: "L2 · payment view", jwt: built.networkView?.serialized ?? "" },
            { label: "L3a", jwt: built.l3a?.serialized ?? "" },
          ]}
        />
      </div>
      <Alert variant="info">
        <Layers />
        <AlertTitle>All three layers are submitted together</AlertTitle>
        <AlertDescription>
          <p>
            A verifier can't check anything from one layer alone. It re-links the bundle via <code>cnf</code> (key
            delegation) and <code>sd_hash</code> (byte binding) and validates the whole chain L1 → L2 → L3. Drop any
            layer and there is nothing to verify — the recipient just gets a different <em>view</em> of the same L2.
          </p>
        </AlertDescription>
      </Alert>
    </div>
  );
}

function ViewColumn({
  icon, title, sees, hidden, mandates, bundle,
}: {
  icon: string;
  title: string;
  sees: string[];
  hidden: string[];
  mandates: string[];
  bundle: { label: string; jwt: string }[];
}) {
  return (
    <Card className="gap-3 py-4">
      <CardContent className="space-y-3">
        <div className="flex items-center gap-2 font-semibold">
          <span>{icon}</span> {title}
        </div>
        <div className="space-y-1.5">
          {sees.map((x) => (
            <div key={x} className="flex items-center gap-1.5 text-sm">
              <Eye className="text-success size-3.5 shrink-0" /> {x}
            </div>
          ))}
          {hidden.map((x) => (
            <div key={x} className="text-muted-foreground flex items-center gap-1.5 text-sm">
              <EyeOff className="size-3.5 shrink-0" /> <span className="line-through">{x}</span>
            </div>
          ))}
        </div>
        {mandates.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {mandates.map((m) => (
              <Badge key={m} variant="muted" className="font-mono text-[10px]">{m}</Badge>
            ))}
          </div>
        )}
        <div>
          <p className="text-muted-foreground mb-1 text-[10px] tracking-wide uppercase">
            Submission bundle — 3 SD-JWTs, sent together
          </p>
          <div className="bg-muted/50 space-y-1 rounded-md border p-2">
            {bundle.map((b) => (
              <div key={b.label} className="flex items-center gap-2">
                <Badge variant="outline" className="w-28 shrink-0 justify-start font-mono text-[9px]">{b.label}</Badge>
                <code className="text-muted-foreground truncate font-mono text-[9px]">{b.jwt}</code>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function VerifyArtifact({ built, scenario }: { built: Built; scenario: ScenarioDef }) {
  const enforced = built.networkEnforced ?? [];
  return (
    <div className="space-y-3">
      <ResultAlert label="💳 Payment network" role="network" result={built.networkResult} />
      {built.merchantResult && <ResultAlert label="🛍️ Merchant" role="merchant" result={built.merchantResult} />}

      {(built.pairCount ?? 1) > 1 && (
        <p className="text-muted-foreground text-xs">
          <span className="text-foreground font-medium">{built.pairCount} mandate pairs</span> were paired and verified
          independently from the one L2.
        </p>
      )}

      {enforced.length > 0 && (
        <Alert variant="info">
          <ShieldCheck />
          <AlertTitle>Network-enforced — you enforce these statefully</AlertTitle>
          <AlertDescription>
            <p>
              These constraints need cross-transaction state a stateless verifier can't hold, so the library surfaces
              them for the payment network to enforce:
            </p>
            <div className="flex flex-wrap gap-1 pt-1">
              {enforced.map((t) => (
                <Badge key={t} variant="warning" className="font-mono text-[10px]">{t}</Badge>
              ))}
            </div>
          </AlertDescription>
        </Alert>
      )}

      {scenario.outcome === "blocked" && (
        <p className="text-muted-foreground text-xs">
          The chain fails closed: any broken signature, binding, or constraint stops the transaction.
        </p>
      )}
    </div>
  );
}

function ResultAlert({ label, role, result }: { label: string; role: "network" | "merchant"; result?: Built["networkResult"] }) {
  if (!result) return null;
  const ok = result.valid;
  return (
    <Alert variant={ok ? "success" : "destructive"}>
      {ok ? <ShieldCheck /> : <ShieldX />}
      <AlertTitle className="flex items-center gap-2">
        {label} — {ok ? "authorized" : "rejected"}
        <Badge variant={ok ? "success" : "destructive"}>{ok ? "valid" : "invalid"}</Badge>
      </AlertTitle>
      <AlertDescription>
        {ok ? (
          <p>
            Signature chain, <code className="font-mono">sd_hash</code> binding
            {role === "network" ? ", and per-transaction constraints" : ""} all verified
            {result.mode ? ` (${result.mode.toLowerCase()} mode)` : ""}.
          </p>
        ) : (
          <ul className="list-disc pl-4">
            {result.errors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        )}
      </AlertDescription>
    </Alert>
  );
}

function Footer() {
  return (
    <footer className="text-muted-foreground mt-12 flex flex-wrap items-center gap-x-4 gap-y-1 border-t pt-4 text-xs">
      <span>Built on the <code className="font-mono">verifiable-intent</code> library — SD-JWT via @sd-jwt/core, ES256 via WebCrypto.</span>
      <a href="https://github.com/lukasjhan/verifiable-intent" className="hover:text-foreground inline-flex items-center gap-1">
        <ExternalLink className="size-3.5" /> source
      </a>
    </footer>
  );
}
