import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";
import Settings from "./Settings";
import AdminUsers from "./AdminUsers";
import AdminAudit from "./AdminAudit";

type Tab = "settings" | "users" | "audit";

// Consolidates the previously scattered /settings, /admin/users, and
// /admin/audit pages under one nav entry. Admin-only (tightened from
// today's behavior, where Agent settings was open to every operator) -
// enforced here, not just by hiding the nav link, since a non-admin could
// otherwise still reach this route directly by URL.
export default function AdminHome() {
  const { data: me, isLoading } = useQuery({ queryKey: ["me"], queryFn: api.me, retry: false });
  const [tab, setTab] = useState<Tab>("settings");

  if (isLoading) return <div className="loading-block">Loading...</div>;

  if (me?.role !== "admin") {
    return (
      <section className="page-stack">
        <header className="page-header">
          <div>
            <span className="eyebrow">Admin</span>
            <h1>Admin</h1>
            <p>You need an administrator role to view this page.</p>
          </div>
        </header>
      </section>
    );
  }

  return (
    <section className="page-stack">
      <div className="tab-bar">
        {(["settings", "users", "audit"] as Tab[]).map((t) => (
          <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {/* REQ-CONSOLE-006: the tab opens Settings.tsx, which is
                platform-wide operational config (scan rate policy, LLM
                provider, NVD key, tool policy, approval timeout) - only two
                of its seven sections are agent-specific. It must not be
                labeled as if it were agent-only. */}
            {t === "settings" ? "Operational settings" : t === "users" ? "Users" : "Account audit"}
          </button>
        ))}
      </div>
      {tab === "settings" && <Settings />}
      {tab === "users" && <AdminUsers />}
      {tab === "audit" && <AdminAudit />}
    </section>
  );
}
