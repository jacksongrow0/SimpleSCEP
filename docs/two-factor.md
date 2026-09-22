# Two-factor authentication

Every SimpleSCEP account requires a second factor. There is no opt-out, no
per-organization toggle, and no feature gate.

## Why it is mandatory

A magic link proves control of a mailbox, and that is the one factor an attacker
who has compromised a mailbox already holds. Behind it sit certificate
authority private keys in the configured key provider and the authority to destroy their key
versions. A toggle to disable the second factor would be an administrator bypass
with extra steps, and the administrator account is the one worth attacking.

## What a user sees

| Situation                                       | What happens                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| First-time instance setup                       | Verify email → enroll an authenticator → save recovery codes → signed in |
| New invitee                                     | Accept invitation → same enrolment path                                  |
| Existing user, first sign-in after this shipped | Magic link → same enrolment path                                         |
| Returning user                                  | Magic link → 6-digit code (or a passkey) → signed in                     |
| Lost authenticator                              | Magic link → recovery code → **enroll a replacement immediately**        |

Redeeming a recovery code deliberately does **not** produce a session on its own.
The code is used precisely when the authenticator is gone, so granting a session
would leave the account running on a dwindling pile of one-time codes with no
second factor at all. The user registers a replacement on the spot.

## How it is built

The state between "clicked the magic link" and "proved a second factor" lives in
`login_challenge` with its own signed `mfa` cookie. **No `session` row exists
until both factors are complete.**

That is the load-bearing decision. An `auth` cookie means exactly what it meant
before two-factor existed — fully authenticated — so `middleware.Auth` gained no
new logic and a route added later is unreachable without a second factor by
construction rather than by a check somebody has to remember to write.

- **TOTP** (`internal/auth/totp.go`) — RFC 6238, SHA-1/6 digits/30s, one step of
  skew. The secret is sealed with `KeyProvider.Protect` under `totp:<user id>`,
  never hashed: verifying a code means recomputing it. `last_step` refuses a code
  at or below the last accepted step, so a code captured in transit cannot be
  replayed inside its own window.
- **Recovery codes** (`internal/auth/recovery.go`) — ten 16-character Crockford
  base32 codes, stored as a plaintext selector plus an argon2id verifier. The
  split keeps a guess to **one** argon2 computation; hashing whole codes and
  trying all ten would make every wrong guess cost 640 MB of unauthenticated
  work.
- **Passkeys** (`internal/auth/passkey.go`) — optional, and usable instead of a
  code at the prompt. TOTP enrolment stays mandatory because it is the
  recovery-independent floor.
- **Guessing** is bounded by `login_challenge.attempts` (5), not by the
  in-process rate limiter. There is deliberately **no account lockout**: a
  lockout on a mandatory second factor is a denial of service handed to anyone
  who knows a customer's email address.

## Step-up

Destructive actions require a second factor proved within the last
`auth.StepUpGrace` (5 minutes). The protected set is `stepUpPatterns` in
`internal/middleware/stepup.go`, keyed by mux pattern so the list is readable in
one place.

Two tests keep it honest. `TestStepUpPatternsAreRegistered` fails if a guarded
pattern no longer matches any registered route — a rename would otherwise
silently drop the guard. `TestEveryDestructiveShapeIsGuarded` scans every
registered route and requires anything matching `/delete`, `/rotate`, or
`/role` to be either guarded or exempted with a written reason.

**If you add a route that destroys key material, add it to `stepUpPatterns`.**
A key-export route in particular belongs there; none exists today.

## Recovering a locked-out user

**Recovery codes are the only route today.** A user who has lost their
authenticator uses a recovery code, which takes them straight to enrolling a
replacement. A user who has lost both is locked out, and there is no supported
way to let them back in.

That gap is known and temporary — an administrator-facing reset is planned — but
it is worth being explicit that until it ships, "lost the phone and lost the
codes" means the account cannot be recovered without hand-written SQL against
production, which leaves no audit trail and should not become routine.

The reason there is no reset today is structural rather than an oversight. The
RLS policies on `user_totp_credential`, `user_recovery_code` and
`user_webauthn_credential` have **no organization arm**:

```sql
USING (current_setting('app.auth_flow', true) = 'true'
       OR user_id = app_current_uuid('app.user_id'))
```

An administrator acting in their own session therefore cannot see or delete a
colleague's second factor — the database refuses it. That is deliberate: an
administrator who _could_ would be a lateral path from the weakest account in an
organization to the strongest, and it would make mandatory 2FA mean "mandatory
unless you can phish whoever holds the reset button".

### If you build the admin reset page

You will have to resolve that tension rather than route around it. Two options:

- **Add an organization arm to those policies.** Simple, and gives up the
  property above outright.
- **Route the reset through `Repository.AuthFlow`,** which bypasses row security
  entirely, and do the authorisation in Go instead.

The second is the safer shape: the database keeps refusing by default, and the
decision to override it sits in one reviewable function rather than in a policy
that silently applies everywhere. Whichever you pick, the page should require
step-up (`stepUpPatterns` in `internal/middleware/stepup.go`), refuse to act on
the acting administrator's own account, and write an audit event — add the action
constant to `internal/audit/types.go` and to its `Actions` slice at that point,
not before, or the audit filter offers an option that never matches.

## Configuration

There is none. Two-factor authentication is mandatory and has no enable/disable
switch, and nothing about how it presents is settable either: authenticator apps
and passkeys are both labelled `SimpleSCEP`, and the DNS scope of every passkey
is the `APP_URL` hostname.

That scope in particular used to be overridable, and the override could do only
two things — reproduce what the default already does, or invalidate every passkey
ever registered. An authenticator holding a credential for the old scope does not
report an error when the scope changes; it reports that it has no credential for
this site, so the failure arrives as every user losing their second factor at
once with nothing in a log to say why.

## Deploying this the first time

The migration that adds the tables is followed by one that runs `DELETE FROM
session`. **Every user is signed out at deploy.** That is intentional: sessions
minted before this existed were created on a single factor and last 30 days, so
leaving them running would mean the requirement applied to new sign-ins only —
and the accounts used daily would be the last to be covered.

## Local development

With deprecated `KEY_PROVIDER=local` the key provider's AES key is in memory and is
regenerated on every restart, so **an enrolled TOTP secret stops decrypting when
you restart the server**. This is the same behaviour SCEP RA keys already have in
local mode. Run against Google Cloud KMS or Azure Key Vault to avoid it.

Otherwise, clear your own second factor and enroll again:

```sql
SET app.auth_flow = 'true';

DELETE FROM user_totp_credential WHERE user_id = (SELECT id FROM "user" WHERE email = 'you@example.com');
DELETE FROM user_recovery_code   WHERE user_id = (SELECT id FROM "user" WHERE email = 'you@example.com');
DELETE FROM login_challenge      WHERE user_id = (SELECT id FROM "user" WHERE email = 'you@example.com');
DELETE FROM session              WHERE user_id = (SELECT id FROM "user" WHERE email = 'you@example.com');
```

The first line is not optional. `FORCE ROW LEVEL SECURITY` applies to the table
owner as well, and these policies have no arm matching "no context at all", so
without it every `DELETE` matches zero rows and reports success.

This is a development convenience against a throwaway database. It is not the
production recovery path — see above.
