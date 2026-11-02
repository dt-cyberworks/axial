import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { LoginConsent } from "./TestAccounts";
import { testAccountRefusal } from "../lib/testAccounts";

/**
 * REQ-TESTACCT-006/009: the monitor's Authorize step. A monitor that holds test accounts logs in without anyone watching, so activation
 * needs the owner's consent first, given here once and covering exactly the (account, host) pairs listed. Renders nothing for a monitor
 * without a test account.
 */
export default function TestAccountsAuthorize({ engagementId }: { engagementId: string }) {
  const queryClient = useQueryClient();
  const overview = useQuery({ queryKey: ["test-accounts", engagementId], queryFn: () => api.listTestAccounts(engagementId) });
  const [error, setError] = useState<string | null>(null);
  const data = overview.data;
  if (!data || data.accounts.length === 0) {
    return (
      <p className="muted-line">
        Test accounts (a login the Vector Agent can use) are entered on the <Link to={`/engagements/${engagementId}?tab=accounts`}>Test accounts</Link> tab.
      </p>
    );
  }
  return (
    <div>
      <h3>Test accounts: what logs in without anyone watching</h3>
      {error && <div className="error-block">{error}</div>}
      <LoginConsent engagementId={engagementId} canManage={data.can_manage} consent={data.consent} hasAccounts
        onChange={() => queryClient.invalidateQueries({ queryKey: ["test-accounts", engagementId] })}
        onError={(e) => setError(testAccountRefusal((e as Error).message))} />
    </div>
  );
}
