# Account, sign-in and administration

**Who this is for:** everyone who signs in; administrators for the last two sections.
**After this page you can:** sign in for the first time, manage your own password, authenticator and sessions, and, as an admin, invite users and read the account audit.

<!-- ui-labels: Forgot password? | Forgot your password? | Send reset link | Choose a new password | Set new password | Check your e-mail | Sign in | Email | Password | Code | Set your password | New password (min. 12 characters) | Set up two-factor authentication | Can't scan? Enter manually: | Enter your authentication code | Save your backup codes | I've saved these codes — continue | Account | Change password | Current password | Two-factor authentication | Re-enroll two-factor authentication | Confirm | Cancel | Active sessions | Revoke | this device | Log out | Users | Invite a new user | Display name | Role | All users | Disable | Enable | Reset password | Reset MFA | Account audit -->

## Signing in (`/login`)

![The sign-in form with email and password fields](../img/sign-in.png)

Individual accounts with mandatory two-factor authentication. There is no shared password and no public sign-up.

1. Enter your **Email** and **Password**.
2. Enter the 6-digit code from your authenticator app (Google Authenticator, 1Password, Authy or any TOTP app), or one of your one-time backup codes.

A session is never issued from a password alone. The session is held in a cookie that scripts on the page cannot read, and a change made with it has to come from the console itself.

### Your first sign-in

A new account starts with a one-time temporary password that an admin gave you.

1. Sign in with it. The page says *This is your first sign-in — replace the temporary password*; choose a **New password** of at least 12 characters (**Set your password**).
2. **Set up two-factor authentication:** scan the QR code, or use **Can't scan? Enter manually:**, then enter the 6-digit code.
3. **Save your backup codes.** Ten codes are shown **once**; each works once. They are the only way in if you lose your authenticator. Choose **I've saved these codes — continue**.

### Forgot password? (`/forgot-password`, `/reset-password`)

When an administrator has switched e-mail on (**E-mail (SMTP relay)** in [Settings](settings.md)), the sign-in page offers **Forgot password?**. Without e-mail it does not, and an administrator resets the password as before.

1. Enter the e-mail address of your account on **Forgot your password?** and choose **Send reset link**. The page answers the same whether or not the address belongs to an account.
2. Open the link from the message. It works once and expires after 30 minutes. A new request makes the earlier link useless, and at most three links are sent per account per hour.
3. On **Choose a new password**, enter the new password (at least 12 characters) twice and a code from your authenticator app, or one of your backup codes. Choose **Set new password**.
4. You are not signed in by this. All of your sessions end, the lockout is cleared, and you sign in as usual with the new password and your authenticator.

The reset never touches your two-factor authentication. If you also lost the authenticator and your backup codes, an administrator has to **Reset MFA** first. An account that has not finished its first sign-in, and a disabled account, get no link.

### When sign-in fails

Five wrong passwords in a row lock the account for a short time that grows with each further failure, from 30 seconds up to 15 minutes. A code is valid for five minutes and five attempts. Many attempts from one address are refused with *too many sign-in attempts from this address - try again later* for a few minutes (30 attempts in five minutes); this does not affect other addresses. Sessions end after 12 hours without activity or 7 days in total. If you cannot get in, use **Forgot password?** when it is offered, or ask an admin to reset your password or your two-factor authentication. See [Users and two-factor authentication](../guides/users-and-mfa.md).

## Account (`/account`)

![The Account page: change password, two-factor authentication and active sessions](../img/account.png)

- **Change password:** enter the **Current password** and a **New password**. Other sessions are signed out.
- **Two-factor authentication:** **Re-enroll two-factor authentication** (for example on a new phone) asks for your current password, then shows a new QR code. Confirm with a code. It replaces the old secret and the backup codes at once, so save the new ten codes.
- **Active sessions:** every device and browser signed in as you, with when it started, when it was last active and which device it is; yours is marked **this device**. **Revoke** signs one out.
- **Log out** is also in the navigation, one click from anywhere.

Each engagement has one owner, the person who created it. Everyone who is signed in can read every engagement; only its owner or an admin can change it, and only an admin can reassign ownership. See [Roles and ownership](../concepts.md#roles-and-ownership).

## Admin: Users (`/admin`, tab **Users**)

![The Users tab: invite form and the list of all users with their actions](../img/admin-users.png)

*Admin only.* Invite-only accounts: there is no public sign-up.

- **Invite a new user:** **Email**, **Display name** and **Role** (operator or admin). The account is created with a one-time temporary password that is shown **once**: pass it on by another route than the invitation.
- **All users:** a table of every account with its role and status. Change the role from the list, **Disable** or **Enable** an account, **Reset password** (shows a new one-time temporary password) and **Reset MFA** (the user enrols a new authenticator at the next sign-in, for example after a lost phone). You never need the user's own password for these.

The first administrator is created from the command line; see [Quickstart](../quickstart.md#2-create-the-first-administrator).

## Admin: Account audit (`/admin`, tab **Account audit**)

![The Account audit tab: the hash-chained security trail of sign-ins and admin actions](../img/admin-account-audit.png)

*Admin only.* A tamper-evident, hash-chained log of every sign-in, MFA event, password change, session and admin action, with **Time**, **Action**, **Outcome**, **Actor** and **Details**. It is separate from each engagement's [Audit](audit.md) trail. Passwords, codes and session tokens are never written to it.
