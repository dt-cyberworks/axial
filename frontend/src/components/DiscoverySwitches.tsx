import type { Engagement } from "../api/client";

// REQ-COVER-007: one on/off switch per extended-discovery capability. The
// switches only narrow what scope and tool grants already allow.
export type DiscoveryFlags = Pick<
  Engagement,
  "subfinder_enabled" | "crawling_enabled" | "oob_enabled" | "screenshots_enabled"
>;

export const DEFAULT_DISCOVERY_FLAGS: DiscoveryFlags = {
  subfinder_enabled: true,
  crawling_enabled: false,
  oob_enabled: false,
  screenshots_enabled: false,
};

const SWITCHES: { key: keyof DiscoveryFlags; label: string; help: string }[] = [
  {
    key: "subfinder_enabled",
    label: "Passive subdomain sources (subfinder)",
    help: "Asks public data sources for subdomains of your in-scope domains; nothing is sent to your systems.",
  },
  {
    key: "crawling_enabled",
    label: "Crawling and URL history",
    help: "Follows links on in-scope websites (shallow, rate-limited) and reads old URLs from the Wayback Machine and CommonCrawl, then tests the parameterised ones.",
  },
  {
    key: "oob_enabled",
    label: "Out-of-band testing",
    help: "Lets blind-vulnerability checks call back to this platform's own interaction server so they can confirm findings that show no visible response.",
  },
  {
    key: "screenshots_enabled",
    label: "Web screenshots",
    help: "Takes one screenshot of each in-scope web page, so you can spot admin panels and forgotten apps at a glance.",
  },
];

export function discoveryFlagSummary(flags: DiscoveryFlags): string {
  const on = SWITCHES.filter((s) => flags[s.key]).map((s) => s.label);
  return on.length ? on.join(", ") : "none";
}

export default function DiscoverySwitches({
  flags, onChange, disabled = false,
}: { flags: DiscoveryFlags; onChange: (next: DiscoveryFlags) => void; disabled?: boolean }) {
  return (
    <div className="discovery-switches">
      {SWITCHES.map((s) => (
        <label key={s.key} className="toggle-row">
          <input
            type="checkbox"
            checked={flags[s.key]}
            disabled={disabled}
            onChange={(e) => onChange({ ...flags, [s.key]: e.target.checked })}
          />
          <span>
            <strong>{s.label}</strong>
            <span className="muted-line" style={{ display: "block" }}>{s.help}</span>
          </span>
        </label>
      ))}
    </div>
  );
}
