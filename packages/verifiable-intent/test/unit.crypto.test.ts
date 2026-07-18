import { describe, it, expect } from "vitest";
import { generateViKeyPair, jwkThumbprint, sha256, parseLayer } from "../src/index.js";
import { signerFor, verifySignature } from "../src/crypto/webcrypto.js";
import { Jwt } from "@sd-jwt/core";

describe("webcrypto keys + hashing", () => {
  it("generateViKeyPair yields an ES256 P-256 key with a thumbprint kid", async () => {
    const kp = await generateViKeyPair();
    expect(kp.publicJwk.kty).toBe("EC");
    expect(kp.publicJwk.crv).toBe("P-256");
    expect(kp.publicJwk.alg).toBe("ES256");
    expect(kp.publicJwk.kid).toBe(kp.kid);
    expect(kp.kid).toBe(await jwkThumbprint(kp.publicJwk));
  });

  it("two key pairs differ", async () => {
    const [a, b] = await Promise.all([generateViKeyPair(), generateViKeyPair()]);
    expect(a.kid).not.toBe(b.kid);
  });

  it("sha256 is base64url and deterministic", async () => {
    const h = await sha256("hello~");
    expect(h).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(await sha256("hello~")).toBe(h);
    expect(await sha256("hellp~")).not.toBe(h);
  });

  it("ES256 sign/verify round-trips; wrong key fails", async () => {
    const kp = await generateViKeyPair();
    const other = await generateViKeyPair();
    const compact = await new Jwt({ header: { alg: "ES256", typ: "JWT" }, payload: { a: 1 } }).sign(signerFor(kp.privateKey));
    expect(await verifySignature(compact, kp.publicJwk)).toBe(true);
    expect(await verifySignature(compact, other.publicJwk)).toBe(false);
  });

  it("a tampered payload fails verification", async () => {
    const kp = await generateViKeyPair();
    const compact = await new Jwt({ header: { alg: "ES256", typ: "JWT" }, payload: { amount: 100 } }).sign(signerFor(kp.privateKey));
    const [h, , s] = compact.split(".");
    const b64url = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    const tampered = `${h}.${b64url({ amount: 999 })}.${s}`;
    expect(await verifySignature(tampered, kp.publicJwk)).toBe(false);
  });
});

describe("parseLayer", () => {
  it("round-trips header/payload/disclosures from a signed SD-JWT", async () => {
    const kp = await generateViKeyPair();
    const compact = await new Jwt({ header: { alg: "ES256", typ: "sd+jwt" }, payload: { iss: "x", n: 1 } }).sign(signerFor(kp.privateKey));
    const layer = await parseLayer(`${compact}~`);
    expect(layer.header.typ).toBe("sd+jwt");
    expect(layer.payload["iss"]).toBe("x");
    expect(layer.disclosures).toHaveLength(0);
  });
});
