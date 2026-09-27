import { useQuery } from "@tanstack/react-query";
import { NavLink, Navigate, Route, Routes, useParams } from "react-router-dom";

import { api } from "./api/client";
import Dashboard from "./pages/Dashboard";
import EngagementWizard from "./pages/EngagementWizard";
import EngagementEdit from "./pages/EngagementEdit";
import EngagementDetail from "./pages/EngagementDetail";
import RunDetail from "./pages/RunDetail";
import Audit from "./pages/Audit";
import Documentation from "./pages/Documentation";
import Login from "./pages/Login";
import Account from "./pages/Account";
import AdminHome from "./pages/AdminHome";
import GlobalApprovalWatcher from "./components/GlobalApprovalWatcher";
import AuthLayout from "./components/AuthLayout";
import Logo from "./components/Logo";
import { useLogout } from "./lib/useLogout";

function RedirectToEngagement() {
  const { id } = useParams();
  return <Navigate to={`/engagements/${id}`} replace />;
}

// REQ-IAM-002: gates the console behind a resolved session before rendering
// any operator data. A confirmed 401 is already handled globally by
// api/client.ts (redirects to /login) - this just avoids flashing the shell
// in the meantime and knows the caller's role for the admin nav links.
//
// A request that never reaches the server (blocked by a browser extension,
// a cold/failed connection, a network blip) throws a TypeError before
// api/client.ts ever sees a response, so the 401 redirect above never fires.
// Retrying a couple of times absorbs most of those transient failures
// silently; if it's still failing after that, show it instead of leaving
// the operator on a blank page with no way to recover short of a manual
// reload (confirmed live on scan-int: a stuck blank page that a DevTools
// "reload" of just the /auth/me request fixed).
function AuthenticatedShell() {
  const { data: me, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["me"],
    queryFn: api.me,
    retry: (failureCount, err) => failureCount < 2 && err instanceof TypeError,
    retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 4000),
  });
  // Hooks run unconditionally, before the early returns below.
  const logout = useLogout();

  if (isLoading) return null;
  if (isError) {
    return (
      <AuthLayout title="Can't reach the server" subtitle="The console couldn't verify your session.">
        <div className="error-block">{error instanceof Error ? error.message : "Network error."}</div>
        <button onClick={() => refetch()} disabled={isFetching} style={{ width: "100%", marginTop: 12 }}>
          {isFetching ? "Retrying…" : "Retry"}
        </button>
      </AuthLayout>
    );
  }
  if (!me) return null; // request() is already redirecting to /login

  return (
    <div className="app-shell">
      {/* REQ-APPROVALUI-001: pending approvals surface on any page, not only Run detail. */}
      <GlobalApprovalWatcher />
      <aside className="sidebar">
        <div className="brand-block">
          <Logo size={34} withWordmark />
        </div>
        <nav className="side-nav" aria-label="Primary">
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/new">New engagement</NavLink>
          <NavLink to="/docs">Documentation</NavLink>
          {me.role === "admin" && <NavLink to="/admin">Admin</NavLink>}
          {/* REQ-CONSOLE-005: a fixed destination label. The display name is a
              subtitle ("who am I signed in as"), never the nav label itself -
              a user called "Test Account" otherwise read as its own section. */}
          <NavLink to="/account" className="nav-account">
            <span>Account</span>
            <span className="nav-account-user" title={me.display_name}>{me.display_name}</span>
          </NavLink>
          {/* issue #11: logout reachable in one click from anywhere, not only
              after first navigating into Account. */}
          <button className="nav-logout" onClick={() => void logout()}>Log out</button>
        </nav>
      </aside>
      <main className="workspace">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/new" element={<EngagementWizard />} />
          <Route path="/docs" element={<Documentation />} />
          <Route path="/account" element={<Account />} />
          <Route path="/admin" element={<AdminHome />} />
          <Route path="/engagements/:id" element={<EngagementDetail />} />
          <Route path="/engagements/:id/runs/:runId" element={<RunDetail />} />
          <Route path="/engagements/:id/edit" element={<EngagementEdit />} />
          <Route path="/engagements/:id/audit" element={<Audit />} />
          {/* Old engagement-scoped views fold into the new engagement/run pages. */}
          <Route path="/engagements/:id/live" element={<RedirectToEngagement />} />
          <Route path="/engagements/:id/results" element={<RedirectToEngagement />} />
          {/* Legacy direct links to the old separate pages fold into the Admin hub. */}
          <Route path="/settings" element={<Navigate to="/admin" replace />} />
          <Route path="/admin/users" element={<Navigate to="/admin" replace />} />
          <Route path="/admin/audit" element={<Navigate to="/admin" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/*" element={<AuthenticatedShell />} />
    </Routes>
  );
}
