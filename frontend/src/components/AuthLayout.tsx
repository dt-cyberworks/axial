import type { ReactNode } from "react";

import Logo from "./Logo";

export default function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="auth-brand">
          <Logo size={34} withWordmark />
        </div>
        <h1 style={{ fontSize: "1.2rem", margin: "0 0 4px" }}>{title}</h1>
        {subtitle && <p className="muted-line" style={{ marginBottom: 16 }}>{subtitle}</p>}
        {children}
      </div>
    </div>
  );
}
