# The SimpleSCEP Entra application

Each SimpleSCEP deployment uses **one** multi-tenant Entra application. The
deployment operator registers and maintains it, and connected directories grant
that application admin consent. SimpleSCEP then calls Intune with the configured
application credentials. The connection flow is described in [scep.md](scep.md).

Register it in a tenant controlled by the deployment operator. It is shared by
the directories connected to that deployment.

## Configuration

| Setting | Value |
| --- | --- |
| Supported account types | **Accounts in any organizational directory** (`signInAudience: AzureADMultipleOrgs`) |
| Redirect URIs (platform **Web**) | `{APP_URL}/integrations/intune/signin/callback`, `{APP_URL}/integrations/intune/consent/callback` |
| Certificates & secrets | One client secret, held only by the deployment operator |
| Branding & properties | Optional deployment logo and home page URL |
| Publisher | Verified publisher domain **and** Microsoft verified publisher (MPN ID) |

### API permissions

Four entries, and all four matter:

| API | Type | Permission | Why |
| --- | --- | --- | --- |
| Intune | Application | `scep_challenge_provider` | Validating challenges and reporting enrollment outcomes. The portal lists it as *SCEP challenge validation*; the manifest value is `scep_challenge_provider`. |
| Microsoft Graph | Application | `Application.Read.All` | `internal/scep/intune.go` resolves the tenant's Intune service URLs through `GET /v1.0/servicePrincipals/appId=0000000a-.../endpoints`. See [Why Graph at all](#why-graph-at-all) below — this is the permission to try to narrow. |
| Microsoft Graph | Delegated | `openid`, `profile` | The sign-in leg that proves which directory the consenting administrator belongs to. Needs no admin consent of its own. |

Revocation uses a second Intune service (`PkiConnectorFEService`) but is
discovered from the same Graph endpoint list and authorized with the same Intune
token, so it needs **no additional permission**.

The `requiredResourceAccess` block:

```json
[
  {
    "resourceAppId": "0000000a-0000-0000-c000-000000000000",
    "resourceAccess": [
      { "id": "b8f4a5b3-5b8f-4e39-9b5a-4d2b3e2f9a11", "type": "Role" }
    ]
  },
  {
    "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      { "id": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30", "type": "Role" },
      { "id": "37f7f235-527c-4136-accd-4a02d197296e", "type": "Scope" },
      { "id": "14dad69e-099b-42c9-810b-d002981feec1", "type": "Scope" }
    ]
  }
]
```

The Graph IDs are the well-known ones for `Application.Read.All`, `openid`, and
`profile`. **Confirm the Intune `scep_challenge_provider` role ID against your own
tenant** — read it from `GET /v1.0/servicePrincipals(appId='0000000a-0000-0000-c000-000000000000')?$select=appRoles`
rather than trusting the value above — then add the permissions through the portal
so the IDs come from Microsoft rather than from this file.

### Why Graph at all

Intune's service URLs are per-tenant — they name the scale unit the tenant sits
on (`https://fef.msuXX.manage.microsoft.com/...`), so they cannot be hardcoded.
Microsoft's reference library discovers them the same way, and our port keeps
that behaviour. `serviceEndpoint` caches the map per tenant and drops it on
failure, so a tenant moved between scale units is rediscovered rather than
breaking permanently. That rediscovery is why the permission has to stay granted
rather than being used once at connect time.

`Application.Read.All` is read-only and cannot read credential *values* — Graph
never returns those — but it does expose the tenant's whole application and
service principal inventory, which is more than this needs and more than some
directory administrators will want on a consent screen.

**Worth testing before launch:** `ServicePrincipalEndpoint.Read.All` ("Read
service principal endpoints") exists as an application role on the Graph service
principal and is scoped to exactly this navigation property. Microsoft publishes
no API mapping for it, so whether it authorizes
`GET /servicePrincipals/appId=.../endpoints` is undocumented and has to be
established empirically — see the test in the pull request discussion. If it
works, use it instead and drop `Application.Read.All`; the consent screen then
reads "Read service principal endpoints" rather than "Read all applications".

For calibration, SCEPman asks for `Directory.Read.All`, which is broader still.

### Distinguishing the two permissions in the field

They fail differently, which is worth knowing when a directory connection fails:

- Missing **Graph** permission → `Intune service discovery failed (403 Forbidden)`
  carrying Graph's "Insufficient privileges to complete the operation"
  (`intune.go:216`).
- Missing **Intune** role, or Intune not licensed → discovery succeeds but the
  list has no SCEP service: `Intune did not publish a
  ScepRequestValidationFEService endpoint for this tenant` (`intune.go:245`).

### Publisher verification

Not cosmetic. Without it the consent screen labels the application unverified,
and tenants with a restrictive app-consent policy block it outright — which for a
security product is the difference between onboarding and not. Verify the
publisher domain, then complete Microsoft verified publisher with the MPN ID.

Do not enable *Assignment required* on the enterprise application.

## Deployment

```
INTUNE_APP_CLIENT_ID=
INTUNE_APP_CLIENT_SECRET=
```

Leaving both blank disables the connector: the revocation worker does not start
and connecting reports "the Intune connector is not deployed" rather than
failing obscurely.

The consent state cookie is signed with `AUTH_SECRET`, so rotating that secret
invalidates any connection flow in progress. Already-connected tenants are
unaffected — only the directory ID is stored.

## Secret rotation

This one secret gates **every** Intune integration on the deployment, and Entra caps
client secrets at 24 months. Rotate well before expiry:

1. Add a second client secret in **Certificates & secrets**. Entra allows both to
   be live at once, so there is no downtime window.
2. Deploy with `INTUNE_APP_CLIENT_SECRET` set to the new value.
3. Confirm enrollments still validate, then delete the old secret.

Nothing changes in connected directories: consent is granted to the application, not to a
credential.

## When Intune enrollments start failing everywhere at once

In rough order of likelihood: the client secret expired; `Application.Read.All`
was removed or its admin consent revoked; Microsoft changed the
Intune wire format, in which case diff `internal/scep/intune.go` against the
reference files named in its header comment.

A failure for a *single* directory is more likely to be local to that directory:
the SimpleSCEP enterprise application was deleted or consent was revoked.
Reconnect it from the SCEP tab.
