import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import type { ViLayer } from "@/scenarios";

export interface Highlight {
  /** Claim / concept name (often the actual SD-JWT field). */
  label: string;
  /** The concrete value that goes in. */
  value: string;
  /** One line on what it means / how it's used. */
  note?: string;
  mono?: boolean;
}

export function LayerCard({
  title,
  subtitle,
  layer,
  highlights,
  accent = "primary",
  rawOpen,
  onRawOpenChange,
}: {
  title: string;
  subtitle: string;
  layer: ViLayer;
  highlights: Highlight[];
  accent?: "primary" | "success" | "warning";
  /** When provided, the Raw SD-JWT section is controlled (so sibling cards open together). */
  rawOpen?: boolean;
  onRawOpenChange?: (open: boolean) => void;
}) {
  const barColor = accent === "success" ? "bg-success" : accent === "warning" ? "bg-warning" : "bg-primary";
  const controlled = onRawOpenChange !== undefined;
  const accordionProps = controlled
    ? { value: rawOpen ? "raw" : "", onValueChange: (v: string) => onRawOpenChange(v === "raw") }
    : {};
  return (
    <Card className="relative gap-3 overflow-hidden py-4">
      <div className={`absolute inset-y-0 left-0 w-1 ${barColor}`} />
      <CardHeader className="gap-1">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm">{title}</CardTitle>
          <Badge variant="muted" className="font-mono">typ: {String(layer.header.typ)}</Badge>
        </div>
        <p className="text-muted-foreground text-xs">{subtitle}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        <dl className="space-y-2 text-xs">
          {highlights.map((h) => (
            <div key={h.label}>
              <div className="flex items-baseline justify-between gap-3">
                <dt className="text-muted-foreground shrink-0 font-mono">{h.label}</dt>
                <dd className={h.mono ? "truncate font-mono text-[11px]" : "text-right font-medium"}>{h.value}</dd>
              </div>
              {h.note && <p className="text-muted-foreground/80 mt-0.5 text-[11px] leading-snug">{h.note}</p>}
            </div>
          ))}
        </dl>
        <Accordion type="single" collapsible {...accordionProps}>
          <AccordionItem value="raw" className="border-b-0">
            <AccordionTrigger className="text-muted-foreground py-1.5 text-xs">Raw SD-JWT</AccordionTrigger>
            <AccordionContent>
              <div className="space-y-2">
                <div>
                  <p className="text-muted-foreground mb-1 text-[10px] tracking-wide uppercase">Decoded payload</p>
                  <pre className="bg-muted/60 max-h-56 overflow-auto rounded-md p-2 font-mono text-[10px] leading-relaxed">
                    {JSON.stringify(layer.payload, null, 2)}
                  </pre>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1 text-[10px] tracking-wide uppercase">Compact serialization</p>
                  <pre className="bg-muted/60 max-h-32 overflow-auto rounded-md p-2 font-mono text-[10px] break-all whitespace-pre-wrap">
                    {layer.serialized}
                  </pre>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
}
