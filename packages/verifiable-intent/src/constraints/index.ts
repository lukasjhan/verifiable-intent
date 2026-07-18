/**
 * Constraint evaluation (constraints.md §4, §5.4) — port of the reference `constraint_checker.py`.
 *
 * Constraints appear only in Autonomous L2 mandates. The verifier builds a "fulfillment" object
 * from the L3 legs and checks each L2 constraint against it. Unknown types follow the strictness
 * mode: PERMISSIVE skips, STRICT violates; an unknown constraint on an `*.open.1` mandate is
 * ALWAYS a violation regardless of mode.
 *
 * Network-enforced constraints (budget, recurrence, agent_recurrence) require cross-transaction
 * state a stateless verifier cannot hold — they are recorded as `checked`, not evaluated here.
 */
import { CONSTRAINT_TYPE, STRICTNESS } from "../constants.js";
import { delegateRefHash } from "../crypto/disclosure.js";
import type {
  Constraint,
  ConstraintCheckResult,
  ConstraintType,
  Strictness,
} from "../types.js";

const KNOWN_TYPES = new Set<string>(Object.values(CONSTRAINT_TYPE));

export interface CheckConstraintsOptions {
  mode?: Strictness;
  /** If true, unknown constraint types are rejected regardless of mode (open mandates). */
  isOpenMandate?: boolean;
  /** Per-type strictness overrides. */
  constraintPolicy?: Record<string, Strictness>;
}

type Fulfillment = Record<string, unknown>;

/** Check that fulfillment values satisfy all constraints. */
export function checkConstraints(
  constraints: readonly Constraint[],
  fulfillment: Fulfillment,
  opts: CheckConstraintsOptions = {},
): ConstraintCheckResult {
  const result: ConstraintCheckResult = { satisfied: true, violations: [], checked: [], skipped: [] };
  const mode = opts.mode ?? STRICTNESS.PERMISSIVE;

  for (const c of constraints) {
    const type = (c as { type: ConstraintType }).type;
    switch (type) {
      case CONSTRAINT_TYPE.AMOUNT_RANGE:
        checkAmount(c as Record<string, unknown>, fulfillment, result);
        break;
      case CONSTRAINT_TYPE.ALLOWED_PAYEES:
        checkAllowlist(c as Record<string, unknown>, fulfillment, "payee", type, result);
        break;
      case CONSTRAINT_TYPE.ALLOWED_MERCHANTS:
        checkAllowlist(c as Record<string, unknown>, fulfillment, "merchant", type, result);
        break;
      case CONSTRAINT_TYPE.LINE_ITEMS:
        checkLineItems(c as Record<string, unknown>, fulfillment, result);
        break;
      case CONSTRAINT_TYPE.REFERENCE:
      case CONSTRAINT_TYPE.BUDGET:
      case CONSTRAINT_TYPE.RECURRENCE:
      case CONSTRAINT_TYPE.AGENT_RECURRENCE:
        // Reference is checked by the integrity layer; budget/recurrence are network-enforced.
        result.checked.push(type);
        break;
      default: {
        const effective = opts.constraintPolicy?.[type] ?? mode;
        if (opts.isOpenMandate || effective === STRICTNESS.STRICT) {
          fail(result, `Unknown constraint type: ${type}`);
        } else {
          result.skipped.push(type);
        }
      }
    }
  }
  return result;
}

export function isKnownConstraint(type: string): boolean {
  return KNOWN_TYPES.has(type);
}

// ---------------------------------------------------------------------------

function fail(result: ConstraintCheckResult, message: string): void {
  result.satisfied = false;
  result.violations.push(message);
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && typeof v !== "boolean" ? v : null;
}

function checkAmount(c: Record<string, unknown>, f: Fulfillment, result: ConstraintCheckResult): void {
  result.checked.push(CONSTRAINT_TYPE.AMOUNT_RANGE);
  const pa = f["payment_amount"];
  if (typeof pa !== "object" || pa === null) return fail(result, "Missing or invalid payment_amount in fulfillment");
  const amount = num((pa as Record<string, unknown>)["amount"]);
  if (amount === null) return fail(result, "Missing/invalid amount in fulfillment payment_amount");

  const currency = (c["currency"] as string) ?? "USD";
  const min = c["min"] !== undefined ? num(c["min"]) : null;
  const max = c["max"] !== undefined ? num(c["max"]) : null;
  if (c["min"] !== undefined && min === null) return fail(result, "Constraint min must be an integer");
  if (c["max"] !== undefined && max === null) return fail(result, "Constraint max must be an integer");
  if (min !== null && amount < min) fail(result, `Amount below minimum: ${amount} < ${min} ${currency}`);
  if (max !== null && amount > max) fail(result, `Amount exceeds maximum: ${amount} > ${max} ${currency}`);

  const fCurrency = (pa as Record<string, unknown>)["currency"] ?? currency;
  if (fCurrency !== currency) fail(result, `Currency mismatch: expected ${currency}, got ${String(fCurrency)}`);
}

/** Shared allowed_payees / allowed_merchants check (target = "payee" | "merchant"). */
function checkAllowlist(
  c: Record<string, unknown>,
  f: Fulfillment,
  target: "payee" | "merchant",
  type: string,
  result: ConstraintCheckResult,
): void {
  result.checked.push(type);
  const subject = f[target];
  if (typeof subject !== "object" || subject === null) return fail(result, `Missing or invalid ${target} in fulfillment`);

  const allowed = Array.isArray(c["allowed"]) ? (c["allowed"] as unknown[]) : null;
  if (!allowed) return fail(result, `${type} 'allowed' must be a list`);
  if (allowed.length === 0) return fail(result, `${type} constraint missing required 'allowed' field`);

  // Prefer resolved merchants from fulfillment; else fall back to inline (non-ref) allow entries.
  let resolved = Array.isArray(f["allowed_merchants"]) ? (f["allowed_merchants"] as unknown[]) : [];
  if (resolved.length === 0) {
    resolved = allowed.filter((m) => isObj(m) && delegateRefHash(m) === null && (m["id"] || m["name"]));
  }
  if (resolved.length === 0) {
    if (allowed.every((m) => delegateRefHash(m) !== null)) {
      result.checked.push(`${type} (skipped: no resolved entries)`);
      return;
    }
    return fail(result, `${type} constraint present but no entries resolved`);
  }

  if (!resolved.some((m) => merchantMatches(m, subject as Record<string, unknown>))) {
    const s = subject as Record<string, unknown>;
    fail(result, `${target} ${String(s["name"] ?? "")} (id=${String(s["id"] ?? "")}) not in allowed list`);
  }
}

function checkLineItems(c: Record<string, unknown>, f: Fulfillment, result: ConstraintCheckResult): void {
  result.checked.push(CONSTRAINT_TYPE.LINE_ITEMS);
  const items = Array.isArray(c["items"]) ? (c["items"] as Record<string, unknown>[]) : [];
  if (items.length === 0) return fail(result, "line_items constraint must have at least one item entry");

  const allowedIds = new Set<string>();
  let hasWildcard = false;
  let totalQtyLimit = 0;
  for (const entry of items) {
    const acceptable = Array.isArray(entry["acceptable_items"]) ? (entry["acceptable_items"] as unknown[]) : [];
    if (acceptable.length === 0) hasWildcard = true;
    const qty = num(entry["quantity"]);
    if (qty === null || qty <= 0) return fail(result, "line_items item quantity must be a positive integer");
    totalQtyLimit += qty;
    for (const ai of acceptable) {
      if (isObj(ai) && delegateRefHash(ai) === null) {
        const id = ai["id"] ?? ai["sku"];
        if (typeof id === "string") allowedIds.add(id);
      }
    }
  }

  const lineItems = Array.isArray(f["line_items"]) ? (f["line_items"] as Record<string, unknown>[]) : null;
  if (lineItems === null) return fail(result, "line_items must be a list");
  if (lineItems.length === 0) return fail(result, "Empty line_items does not satisfy line_items constraint");

  let totalQty = 0;
  for (const li of lineItems) {
    const id = (li["id"] ?? li["sku"]) as string | undefined;
    if (!id) return fail(result, "Line item missing 'id' field");
    const qty = num(li["quantity"]) ?? 0;
    if (qty < 0) return fail(result, `Negative quantity for item ${id}`);
    if (allowedIds.size > 0 && !allowedIds.has(id) && !hasWildcard) {
      fail(result, `Item ${id} not in acceptable items: ${[...allowedIds].sort().join(", ")}`);
    }
    totalQty += qty;
  }
  if (totalQty > totalQtyLimit) fail(result, `Total quantity ${totalQty} exceeds limit ${totalQtyLimit}`);
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** Match two merchants by id if both have it, else by name+website. */
function merchantMatches(candidate: unknown, target: Record<string, unknown>): boolean {
  if (!isObj(candidate)) return false;
  const cId = candidate["id"];
  const tId = target["id"];
  if (cId && tId) return cId === tId;
  return (
    !!candidate["name"] &&
    candidate["name"] === target["name"] &&
    !!candidate["website"] &&
    candidate["website"] === target["website"]
  );
}
