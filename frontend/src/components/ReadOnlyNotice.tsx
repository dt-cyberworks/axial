import type { Engagement } from "../api/client";

/**
 * REQ-IAM-025: shown on an engagement the signed-in user may read but not change.
 * Everyone can read every engagement; only its owner or an administrator can
 * change it, and the server refuses a change from anyone else (403). The notice
 * says whose it is, so the reader knows whom to ask.
 */
export default function ReadOnlyNotice({ engagement }: { engagement: Pick<Engagement, "owner_name" | "owner_email"> }) {
  const owner = engagement.owner_name
    ? `${engagement.owner_name}${engagement.owner_email ? ` (${engagement.owner_email})` : ""}`
    : "its owner";
  return (
    <div className="read-only-notice" role="note">
      You can read this engagement, but only {owner} or an administrator can change it.
    </div>
  );
}
