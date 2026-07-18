import { describe, it, expect } from "vitest";
import { parseLayer, presentL2ForMerchant, presentL2ForNetwork, resolveDisclosures, VI_VCT } from "../src/index.js";
import { keys, makeL1, autonomousL2 } from "./helpers.js";

async function delegateVcts(serialized: string): Promise<string[]> {
  const l2 = await parseLayer(serialized);
  const claims = await resolveDisclosures(l2.payload, l2.disclosureStrings);
  const dels = Array.isArray(claims["delegate_payload"]) ? (claims["delegate_payload"] as any[]) : [];
  return dels.map((d) => d?.vct).filter(Boolean);
}

describe("selective presentation privacy boundary", () => {
  it("network view reveals only the payment mandate (+ a merchant), never checkout", async () => {
    const k = await keys();
    const l2 = await autonomousL2(await makeL1(k), k);
    const view = await presentL2ForNetwork(l2);
    expect(view.disclosures).toHaveLength(2);
    const vcts = await delegateVcts(view.serialized);
    expect(vcts).toContain(VI_VCT.PAYMENT_OPEN);
    expect(vcts).not.toContain(VI_VCT.CHECKOUT_OPEN);
  });

  it("merchant view reveals only the checkout mandate (+ an item), never payment", async () => {
    const k = await keys();
    const l2 = await autonomousL2(await makeL1(k), k);
    const view = await presentL2ForMerchant(l2);
    expect(view.disclosures).toHaveLength(2);
    const vcts = await delegateVcts(view.serialized);
    expect(vcts).toContain(VI_VCT.CHECKOUT_OPEN);
    expect(vcts).not.toContain(VI_VCT.PAYMENT_OPEN);
  });

  it("the full L2 exposes both mandates", async () => {
    const k = await keys();
    const l2 = await autonomousL2(await makeL1(k), k);
    const vcts = await delegateVcts(l2.serialized);
    expect(vcts).toContain(VI_VCT.CHECKOUT_OPEN);
    expect(vcts).toContain(VI_VCT.PAYMENT_OPEN);
  });
});
