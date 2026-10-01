import type { ScanProfile } from "../api/client";

// REQ-PIPE-005: how deep a scan goes. Standard picks its checks from what the
// scan finds; thorough runs every template on every web service. Neither
// widens scope, tool grants or the discovery switches.
export const SCAN_DEPTHS: { value: ScanProfile; label: string; help: string }[] = [
  {
    value: "standard",
    label: "Standard",
    help: "Checks are chosen from what the scan finds: only the templates for the technologies it identified, plus the generic ones. Faster, and the plan shows what ran and why.",
  },
  {
    value: "thorough",
    label: "Thorough",
    help: "Every template on every web service, whatever the scan identified, plus a deep sweep of about 30,000 likely paths per web service (roughly 25 minutes each). Much slower; use it when a complete sweep matters more than time.",
  },
];

export function scanDepthLabel(value: ScanProfile | null | undefined): string {
  return SCAN_DEPTHS.find((d) => d.value === value)?.label ?? "Standard";
}

export default function ScanDepth({
  value, onChange, disabled = false,
}: { value: ScanProfile; onChange: (next: ScanProfile) => void; disabled?: boolean }) {
  return (
    <fieldset className="scan-depth" disabled={disabled}>
      <legend className="visually-hidden">Scan depth</legend>
      {SCAN_DEPTHS.map((d) => (
        <label key={d.value} className="toggle-row">
          <input
            type="radio" name="scan-depth" value={d.value} checked={value === d.value}
            onChange={() => onChange(d.value)}
          />
          <span>
            <strong>{d.label}</strong>
            <span className="muted-line" style={{ display: "block" }}>{d.help}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}
