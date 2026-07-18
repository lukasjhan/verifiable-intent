import { KeyRound, ScrollText, ShieldCheck, ShieldX } from "lucide-react";
import { cn } from "@/lib/utils";
import { ACTOR_META, type Actor, type Built, type StepMeta } from "@/scenarios";

type Kind = "l1" | "l2" | "l2pay" | "l2chk" | "l3a" | "l3b";
interface Chip {
  kind: Kind;
  label: string;
  fresh?: boolean;
}

const CHIP: Record<Kind, { cls: string; tip: string }> = {
  l1: { cls: "border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-300", tip: "L1 — issuer credential (Alice's card, bound to her key)" },
  l2: { cls: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-300", tip: "L2 — user mandate (delegation + constraints)" },
  l2pay: { cls: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-300", tip: "L2 payment view — payment mandate only (cart hidden)" },
  l2chk: { cls: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-300", tip: "L2 checkout view — checkout mandate only (card hidden)" },
  l3a: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300", tip: "L3a — payment proof for the network" },
  l3b: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-300", tip: "L3b — checkout proof for the merchant" },
};

const c = (kind: Kind, label: string, fresh?: boolean): Chip => ({ kind, label, fresh });

/** What each actor is holding at a given step (chips flagged `fresh` were created/received now). */
function holdingsFor(stepId: StepMeta["id"], mode: Built["mode"]): Record<Actor, Chip[]> {
  const e: Record<Actor, Chip[]> = { issuer: [], user: [], agent: [], merchant: [], network: [] };

  if (mode === "IMMEDIATE") {
    if (stepId === "l1") e.user = [c("l1", "L1", true)];
    else if (stepId === "l2") {
      e.user = [c("l1", "L1")];
      e.agent = [c("l1", "L1", true), c("l2", "L2", true)];
    } else if (stepId === "verify") {
      e.user = [c("l1", "L1")];
      e.agent = [c("l1", "L1"), c("l2", "L2")];
      e.network = [c("l1", "L1", true), c("l2", "L2", true)];
      e.merchant = [c("l1", "L1", true), c("l2", "L2", true)];
    }
    return e;
  }

  // AUTONOMOUS
  if (stepId === "l1") e.user = [c("l1", "L1", true)];
  else if (stepId === "l2") {
    e.user = [c("l1", "L1")];
    e.agent = [c("l1", "L1", true), c("l2", "L2", true)];
  } else if (stepId === "l3") {
    e.user = [c("l1", "L1")];
    e.agent = [c("l1", "L1"), c("l2", "L2"), c("l3a", "L3a", true), c("l3b", "L3b", true)];
  } else if (stepId === "route" || stepId === "verify") {
    const fresh = stepId === "route";
    e.user = [c("l1", "L1")];
    e.agent = [c("l1", "L1"), c("l2", "L2"), c("l3a", "L3a"), c("l3b", "L3b")];
    e.network = [c("l1", "L1", fresh), c("l2pay", "L2·pay", fresh), c("l3a", "L3a", fresh)];
    e.merchant = [c("l1", "L1", fresh), c("l2chk", "L2·chk", fresh), c("l3b", "L3b", fresh)];
  }
  return e;
}

const short = (s?: string) => (s ? `${s.slice(0, 6)}…` : "");

export function FlowBoard({
  stepId,
  built,
  active,
  results,
}: {
  stepId: StepMeta["id"];
  built: Built;
  active: Set<Actor>;
  results?: { network?: boolean; merchant?: boolean };
}) {
  const holdings = holdingsFor(stepId, built.mode);
  const order: Actor[] = ["issuer", "user", "agent", "merchant", "network"];
  const roleOf = (a: Actor): { text: string; signer: boolean } => {
    if (a === "issuer") return { text: `🔑 ${short(built.kids.issuer)}`, signer: true };
    if (a === "user") return { text: `🔑 ${short(built.kids.user)}`, signer: true };
    if (a === "agent") return { text: built.kids.agent ? `🔑 ${short(built.kids.agent)}` : "delegated", signer: true };
    return { text: "verifier", signer: false };
  };

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
      {order.map((a) => {
        const on = active.has(a);
        const role = roleOf(a);
        const chips = holdings[a];
        const verdict = stepId === "verify" && results ? (a === "network" ? results.network : a === "merchant" ? results.merchant : undefined) : undefined;
        return (
          <div
            key={a}
            className={cn(
              "flex flex-col rounded-lg border p-2.5 transition-all duration-300",
              on ? "border-primary/60 bg-primary/5 shadow-sm" : "bg-card",
              verdict === false && "border-destructive/50 bg-destructive/5",
              verdict === true && "border-success/50 bg-success/5",
            )}
          >
            <div className="flex items-start gap-1.5">
              <span className="text-lg leading-none">{ACTOR_META[a].icon}</span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-xs font-semibold">{ACTOR_META[a].label}</div>
                <div className="text-muted-foreground flex items-center gap-0.5 truncate font-mono text-[10px]">
                  {role.signer && <KeyRound className="size-2.5 shrink-0" />}
                  <span className="truncate">{role.text}</span>
                </div>
              </div>
              {verdict === true && <ShieldCheck className="text-success size-4 shrink-0" />}
              {verdict === false && <ShieldX className="text-destructive size-4 shrink-0" />}
            </div>

            <div className="mt-2 flex min-h-[3.25rem] flex-col gap-1">
              {chips.length === 0 ? (
                <span className="text-muted-foreground/40 mt-1 text-[10px]">— holds nothing yet —</span>
              ) : (
                chips.map((chip) => (
                  <div
                    key={chip.kind}
                    title={CHIP[chip.kind].tip}
                    className={cn(
                      "flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium",
                      CHIP[chip.kind].cls,
                      chip.fresh && "animate-in fade-in-0 zoom-in-95 ring-primary/40 ring-2 duration-500",
                    )}
                  >
                    <ScrollText className="size-2.5 shrink-0" />
                    <span className="truncate">{chip.label}</span>
                    {chip.fresh && <span className="ml-auto text-[8px] uppercase opacity-70">new</span>}
                  </div>
                ))
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
