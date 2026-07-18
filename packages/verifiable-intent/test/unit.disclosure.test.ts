import { describe, it, expect } from "vitest";
import {
  createDisclosure,
  hashDisclosure,
  createDelegateRef,
  delegateRefHash,
  resolveDisclosures,
  encodePresentation,
  DELEGATE_REF_KEY,
} from "../src/index.js";

describe("disclosure primitives (via @sd-jwt/core)", () => {
  it("object-property vs array-element encoding", () => {
    const obj = createDisclosure("email", "a@b.com", "salt1");
    const arr = createDisclosure(null, { id: "m1" }, "salt2");
    const dec = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString());
    expect(dec(obj)).toEqual(["salt1", "email", "a@b.com"]);
    expect(dec(arr)).toEqual(["salt2", { id: "m1" }]);
  });

  it("hashDisclosure is deterministic and content-sensitive", async () => {
    const d = createDisclosure(null, { id: "m1" }, "s");
    expect(await hashDisclosure(d)).toBe(await hashDisclosure(d));
    const d2 = createDisclosure(null, { id: "m2" }, "s");
    expect(await hashDisclosure(d)).not.toBe(await hashDisclosure(d2));
  });

  it("delegate ref round-trips", async () => {
    const h = await hashDisclosure(createDisclosure(null, { x: 1 }, "s"));
    const ref = createDelegateRef(h);
    expect(ref[DELEGATE_REF_KEY]).toBe(h);
    expect(delegateRefHash(ref)).toBe(h);
    expect(delegateRefHash({ notARef: 1 })).toBeNull();
  });
});

describe("resolveDisclosures", () => {
  it("folds an object-property disclosure listed in _sd", async () => {
    const disc = createDisclosure("email", "a@b.com", "s");
    const payload = { sub: "u", _sd: [await hashDisclosure(disc)], _sd_alg: "sha-256" };
    const claims = await resolveDisclosures(payload, [disc]);
    expect(claims["email"]).toBe("a@b.com");
    expect(claims["_sd"]).toBeUndefined();
  });

  it("resolves delegate_payload array refs to their disclosed values", async () => {
    const m = createDisclosure(null, { vct: "mandate.payment.open.1", n: 1 }, "s");
    const payload = { delegate_payload: [createDelegateRef(await hashDisclosure(m))] };
    const claims = await resolveDisclosures(payload, [m]);
    expect((claims["delegate_payload"] as any[])[0]).toEqual({ vct: "mandate.payment.open.1", n: 1 });
  });

  it("resolves a SHARED disclosure referenced from two places (no duplicate rejection)", async () => {
    const merchant = createDisclosure(null, { id: "m1", name: "Acme" }, "s");
    const h = await hashDisclosure(merchant);
    const checkout = createDisclosure(null, { vct: "mandate.checkout.open.1", constraints: [{ allowed: [createDelegateRef(h)] }] }, "c");
    const payment = createDisclosure(null, { vct: "mandate.payment.open.1", constraints: [{ allowed: [createDelegateRef(h)] }] }, "p");
    const payload = { delegate_payload: [createDelegateRef(await hashDisclosure(checkout)), createDelegateRef(await hashDisclosure(payment))] };
    const claims = await resolveDisclosures(payload, [merchant, checkout, payment]);
    const dels = claims["delegate_payload"] as any[];
    // Both mandates' nested refs resolve to the same merchant object.
    expect(dels[0].constraints[0].allowed[0]).toEqual({ id: "m1", name: "Acme" });
    expect(dels[1].constraints[0].allowed[0]).toEqual({ id: "m1", name: "Acme" });
  });

  it("leaves an unknown ref (undisclosed) untouched", async () => {
    const payload = { delegate_payload: [createDelegateRef("nonexistent-digest")] };
    const claims = await resolveDisclosures(payload, []);
    expect((claims["delegate_payload"] as any[])[0]).toEqual({ [DELEGATE_REF_KEY]: "nonexistent-digest" });
  });
});

describe("encodePresentation", () => {
  it("is byte-identical to the raw ~-join and order-sensitive", async () => {
    // A minimal valid JWT-shaped base segment isn't needed — encodePresentation only re-encodes.
    const base = "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.sig";
    const d1 = createDisclosure(null, { a: 1 }, "s1");
    const d2 = createDisclosure(null, { b: 2 }, "s2");
    expect(await encodePresentation(base, [d1, d2])).toBe(`${base}~${d1}~${d2}~`);
    expect(await encodePresentation(base, [d2, d1])).toBe(`${base}~${d2}~${d1}~`);
  });
});
