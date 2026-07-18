import { describe, it, expect } from "vitest";
import { checkConstraints, CONSTRAINT_TYPE, STRICTNESS, type Constraint } from "../src/index.js";

const merchant = { id: "m1", name: "Acme", website: "https://acme.example" };

describe("checkConstraints — amount_range", () => {
  const c: Constraint = { type: CONSTRAINT_TYPE.AMOUNT_RANGE, currency: "USD", min: 1000, max: 40000 };
  it("passes within range", () => {
    const r = checkConstraints([c], { payment_amount: { currency: "USD", amount: 25000 } });
    expect(r.satisfied).toBe(true);
    expect(r.checked).toContain(CONSTRAINT_TYPE.AMOUNT_RANGE);
  });
  it("fails above max / below min / on currency mismatch", () => {
    expect(checkConstraints([c], { payment_amount: { currency: "USD", amount: 99999 } }).satisfied).toBe(false);
    expect(checkConstraints([c], { payment_amount: { currency: "USD", amount: 500 } }).satisfied).toBe(false);
    expect(checkConstraints([c], { payment_amount: { currency: "EUR", amount: 25000 } }).satisfied).toBe(false);
  });
});

describe("checkConstraints — allowlists", () => {
  it("allowed_payees passes for a listed payee, fails otherwise", () => {
    const c: Constraint = { type: CONSTRAINT_TYPE.ALLOWED_PAYEES, allowed: [merchant] };
    expect(checkConstraints([c], { payee: merchant, allowed_merchants: [merchant] }).satisfied).toBe(true);
    expect(checkConstraints([c], { payee: { id: "m9" }, allowed_merchants: [merchant] }).satisfied).toBe(false);
  });
  it("allowed_merchants passes for a listed merchant, fails otherwise", () => {
    const c: Constraint = { type: CONSTRAINT_TYPE.ALLOWED_MERCHANTS, allowed: [merchant] };
    expect(checkConstraints([c], { merchant, allowed_merchants: [merchant] }).satisfied).toBe(true);
    expect(checkConstraints([c], { merchant: { id: "m9" }, allowed_merchants: [merchant] }).satisfied).toBe(false);
  });
});

describe("checkConstraints — line_items", () => {
  const c: Constraint = {
    type: CONSTRAINT_TYPE.LINE_ITEMS,
    items: [{ id: "li-1", acceptable_items: [{ id: "A", title: "Item A" }], quantity: 2 }],
  };
  it("passes an acceptable item within quantity", () => {
    expect(checkConstraints([c], { line_items: [{ id: "A", quantity: 1 }] }).satisfied).toBe(true);
  });
  it("fails a non-acceptable item or over-quantity", () => {
    expect(checkConstraints([c], { line_items: [{ id: "B", quantity: 1 }] }).satisfied).toBe(false);
    expect(checkConstraints([c], { line_items: [{ id: "A", quantity: 5 }] }).satisfied).toBe(false);
  });
});

describe("checkConstraints — network-enforced are recorded, not evaluated", () => {
  for (const type of [CONSTRAINT_TYPE.BUDGET, CONSTRAINT_TYPE.RECURRENCE, CONSTRAINT_TYPE.AGENT_RECURRENCE, CONSTRAINT_TYPE.REFERENCE]) {
    it(`${type} → checked, satisfied stays true`, () => {
      const r = checkConstraints([{ type } as Constraint], {});
      expect(r.satisfied).toBe(true);
      expect(r.checked).toContain(type);
    });
  }
});

describe("checkConstraints — unknown types + strictness", () => {
  const unknown: Constraint = { type: "urn:example:custom" } as Constraint;
  it("PERMISSIVE skips unknown", () => {
    const r = checkConstraints([unknown], {}, { mode: STRICTNESS.PERMISSIVE });
    expect(r.satisfied).toBe(true);
    expect(r.skipped).toContain("urn:example:custom");
  });
  it("STRICT rejects unknown", () => {
    expect(checkConstraints([unknown], {}, { mode: STRICTNESS.STRICT }).satisfied).toBe(false);
  });
  it("open mandate rejects unknown regardless of mode", () => {
    expect(checkConstraints([unknown], {}, { mode: STRICTNESS.PERMISSIVE, isOpenMandate: true }).satisfied).toBe(false);
  });
  it("per-type policy overrides the global mode", () => {
    const r = checkConstraints([unknown], {}, { mode: STRICTNESS.PERMISSIVE, constraintPolicy: { "urn:example:custom": STRICTNESS.STRICT } });
    expect(r.satisfied).toBe(false);
  });
});
