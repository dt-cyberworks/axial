import { useNavigate } from "react-router-dom";

import { api, clearSession } from "../api/client";

/**
 * One shared logout action (issue #11) - the sidebar and the Account page
 * both call this, so there is exactly one place that defines what "log out"
 * does instead of two copies that could drift.
 */
export function useLogout(): () => Promise<void> {
  const navigate = useNavigate();
  return async () => {
    try { await api.logout(); } catch { /* best effort */ }
    clearSession();
    navigate("/login", { replace: true });
  };
}
