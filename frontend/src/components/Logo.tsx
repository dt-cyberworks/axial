// Single source for the Axial mark (docs/design/axial-brand-design.md).
// Reused by the sidebar brand block and the auth screen so the two never drift.
export default function Logo({
  size = 32,
  withWordmark = false,
}: {
  size?: number;
  withWordmark?: boolean;
}) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
      <svg width={size} height={size} viewBox="0 0 100 100" fill="none" aria-hidden="true">
        <defs>
          <linearGradient id="axialMark" x1="10" y1="10" x2="90" y2="90" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#6C5CE7" />
            <stop offset="1" stopColor="#3D8BFF" />
          </linearGradient>
        </defs>
        <circle cx="50" cy="50" r="45" stroke="rgba(255,255,255,0.12)" strokeWidth="1.5" />
        <path d="M8 22 L8 9 L21 9" stroke="#00D1B2" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M92 22 L92 9 L79 9" stroke="#00D1B2" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M8 78 L8 91 L21 91" stroke="#00D1B2" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M92 78 L92 91 L79 91" stroke="#00D1B2" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
        <path
          d="M50 12 L20 84 M50 12 L80 84 M33 60 L67 60"
          stroke="url(#axialMark)"
          strokeWidth="9"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx="50" cy="60" r="4.5" fill="#A6E6FF" />
      </svg>
      {withWordmark && (
        <span style={{ display: "grid", lineHeight: 1.05 }}>
          <strong style={{ fontFamily: "var(--font-heading)", fontSize: "1.05rem", letterSpacing: "0.02em", color: "var(--text)" }}>
            AXIAL
          </strong>
          <span style={{ fontFamily: "var(--font-heading)", fontSize: "0.62rem", fontWeight: 700, letterSpacing: "0.16em", color: "var(--teal)" }}>
            AGENT
          </span>
        </span>
      )}
    </span>
  );
}
