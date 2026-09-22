# SCEP operations

An organization runs one or more RFC 8894 endpoints, each with its own URL:

`https://your-simple-scep-host/scep/<endpoint-id>`

Every device pointed at an endpoint enrolls through it, whichever MDM sent them and however they authenticate. Use it for `GetCACaps`, `GetCACert`, and `PKIOperation`. HTTPS is required in production. The advertised capabilities are AES-128-CBC, SHA-256, HTTP POST, renewal, and `SCEPStandard`. The legacy switch permits inbound SHA-1/3DES requests but responses remain AES/SHA-256; MD5 and single DES are never accepted.

Endpoints are created from **SCEP · ACME · EST → Add endpoint**, which names the endpoint, binds it to an active issuing CA, and mints its registration authority keypair. The CA binding is fixed once created; the name and everything under Issuance policy can change later.

Give each device population you police differently its own endpoint: validity, renewal window, subject and SAN patterns, permitted extended key usages, and the set of enabled authentication methods are all per-endpoint. That separation is the point — an endpoint's issuance policy is only ever as strong as the loosest authentication method enabled on it, so a shared secret that lets any holder enroll should not sit on the same endpoint as a permissive usage list.

**Deleting one.** Any endpoint can be deleted, including one that has issued certificates, but the consequences are almost all delayed — which is why the dialog enumerates them and will not proceed until the endpoint's name is typed:

- The enrollment URL stops responding immediately, so any MDM profile pointing at it fails every future enrollment.
- Certificates it issued are **not revoked**. They stay valid and trusted until they expire, so nothing looks broken at first. The damage lands when each device reaches its renewal window and finds nothing to renew against, then loses whatever the certificate authenticated.
- Intune can no longer revoke them. The worker matches a serial against the endpoints that issued it; with the endpoint gone its certificates match nothing, Microsoft is told "certificate not found", and the request is acknowledged. Revoking by hand from the certificates page still works and still reaches the CRL and OCSP.
- The enrollment history, unused one-time challenges, the shared secret, and the Jamf Pro webhook password all go with it. The certificates themselves stay listed under Certificates.

If the aim is only to stop new enrollments, turn the endpoint off instead: reversible, immediate, and it leaves renewal, history, and revocation matching intact. If the certificates should stop working, revoke them before deleting, while the endpoint is still there to match them.

## Enrollment authentication

Authentication methods are independent switches on each endpoint, so several can be live at once — an organization running Intune for Windows and Jamf Pro for Macs turns both on and points both at the same endpoint, or splits them across two.

| Method             | How a device gets its password                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| One-time challenge | An administrator generates one from the UI, or `POST /api/scep/endpoints/<endpoint-id>/challenges`. Good for one device or your own automation.                                      |
| Shared secret      | One password every device uses. `POST /api/scep/endpoints/<endpoint-id>/auth/static` rotates it and invalidates the previous one. For MDMs that cannot fetch a challenge per device. |
| Microsoft Intune   | Intune issues the password and Microsoft validates it. Requires connecting the organization's Entra tenant (below).                                                                  |
| Jamf Pro           | Jamf Pro requests a fresh challenge over a webhook per device. It enrolls as a one-time challenge, so that method must stay on.                                                      |

Because a device only ever presents a challenge password, the endpoint it reached decides which method applies from the password itself, in this order:

1. **Renewal** — a `RenewalReq` signed by an unrevoked certificate this endpoint issued, inside the renewal window.
2. **One-time challenge** — `sha256(password)` hits an unused, unexpired `scep_challenge` row.
3. **Shared secret** — the password verifies against the stored argon2id hash.
4. **Microsoft Intune** — Microsoft validates the password.

Cheap local checks run before the Intune round trip, and only a full one-time match consumes a challenge, so a rejected enrollment never burns one. If no enabled method accepts the password, the request is refused and recorded as a failed enrollment with the reason, visible under **Recent enrollments**.

Administration requires an administrator session. Automation should use a dedicated administrator account until service-account authentication is added.

## Extended key usages

The endpoint's issuance policy carries a list of permitted extended key usages, and that list is a ceiling rather than a stamp:

- A request that asks for a subset of it — Windows and most MDMs put an `extendedKeyUsage` extension in the CSR's extension request — is issued **exactly that subset**. One endpoint can therefore serve an Intune Wi-Fi profile asking for client authentication and an S/MIME profile asking for secure email, and neither certificate collects the other's usage.
- A request that asks for nothing — what many SCEP clients send — is issued **client authentication only**, never the whole permitted list. Permitting a usage is a decision about what a device may _ask for_, not a grant to every device that asks for nothing, so widening the endpoint for S/MIME does not put secure-email on every Wi-Fi certificate. An endpoint that does not permit client authentication at all has no safe default and refuses such a request outright.
- A request that asks for a usage the endpoint does not permit is **rejected**, not silently narrowed, and the reason appears under **Recent enrollments**. A profile that promises a usage the endpoint will not issue is a misconfiguration, and failing visibly is better than handing the device a certificate that cannot do the job.

A one-time challenge can pin the usages further. The endpoint's list says what _any_ device may ask for; a challenge's pin says what _this one enrollment_ may ask for, alongside the subject and SANs it already pins. Automation can therefore mint a challenge that can only ever produce an S/MIME certificate. A pin may only narrow the endpoint's list, never widen it, and is compared as a set — order does not matter, unlike the SAN pin. Pinning nothing accepts anything the endpoint allows, which is how every existing challenge behaves. Set it with `expectedEKUs` on `POST /api/scep/endpoints/<endpoint-id>/challenges`, or the checkboxes in the one-time challenge dialog.

Every permitted usage must also be in the issuing CA's own profile. The policy form shows usages the CA cannot carry as disabled rather than hiding them, so the reason a usage is unavailable is visible where the choice is made. Issuance re-checks the CA profile regardless of what the endpoint permits.

Offered: client authentication, server authentication, secure email (S/MIME), code signing, smartcard logon, and the three IPsec usages. Two exclusions are deliberate:

- **OCSP signing is never offerable.** RFC 6960 treats a certificate carrying it as a delegated responder for its issuer, so a device that obtained one could sign `good` responses for certificates the same CA has revoked. That is an escalation out of device enrollment and no policy setting opens it.
- **`anyExtendedKeyUsage` (`2.5.29.37.0`) is rejected everywhere**, including in a CA's own issuance profile where custom dotted OIDs are otherwise accepted. Most validators read it as matching every purpose, which makes a stolen device key usable for server authentication or code signing under an identity this CA vouched for. A deployment needing three usages lists three usages.

Key usage bits follow the purpose rather than the key type alone. digitalSignature is always set, since every issuable purpose signs. The encryption bits are added only for purposes that actually establish a key — client and server authentication, email protection, smartcard logon, and the IPsec usages — so a code-signing certificate no longer carries a keyEncipherment bit it cannot use. RSA establishes keys by transport and gets keyEncipherment; EC establishes by agreement and gets keyAgreement, which is what lets an EC S/MIME certificate receive encrypted mail rather than only sign. A custom dotted OID is treated as possibly needing both, because narrowing bits on a purpose the server cannot reason about would break a deployment silently.

## Microsoft Intune

Intune validation is built in — there is no sidecar and no extra container. The
deployment operator configures one multi-tenant Entra application, and a directory
connects by granting it admin consent. **SCEP · ACME · EST → Microsoft Entra
directory → Connect** starts the flow. See
[intune-app-registration.md](intune-app-registration.md) for registration and maintenance.

**Connect** first shows what Microsoft is about to ask for, and why the Graph
permission is among it. Entra's consent screen is Microsoft's own page and
carries no text from us, so that dialog is the only place an administrator can be
told why a certificate product wants to read applications before they are asked
to approve it. The explanation is in `IntuneConsentDialog` in
`view/home/protocols.templ`; keep it in step with the permissions in
[intune-app-registration.md](intune-app-registration.md).

Connecting then takes two redirects, and both are necessary:

1. **Sign in.** The administrator signs in to Entra. SimpleSCEP redeems the
   authorization code itself, so the `tid` claim in the returned ID token is a
   first-hand statement from Microsoft about which directory they belong to.
2. **Consent**, at a URL pinned to that directory. The callback has to name the
   same one.

Microsoft warns that the `tenant` parameter on a consent callback is
attacker-supplied and is not an authenticated identity. Without the sign-in leg,
anyone could replay another organization's directory ID into their own callback and
bind a tenant they do not own; the two-leg shape is what makes that impossible.
Both legs are bound to the browser by a signed, ten-minute cookie carrying a
nonce echoed as the OAuth `state` parameter, and the connection is only written
after a live client-credentials call into the tenant succeeds.

Only the directory ID is stored. There is no per-directory secret to expire. A
directory backs exactly one SimpleSCEP organization, and an organization connects
exactly one directory — every endpoint it runs enrols through that same tenant,
and Microsoft Intune is then switched on per endpoint. Access tokens and the
tenant's Intune service endpoints are cached in memory, keyed by tenant.

**Disconnect** unbinds the directory here. Consent itself lives in the connected
tenant, where it can be withdrawn by deleting the SimpleSCEP enterprise application
under Entra ID → Enterprise applications.

Entra creates the service principal and applies its role assignments
asynchronously, so a connection attempted seconds after consent may report that
Microsoft has not finished applying it. That is propagation, not
misconfiguration — retrying a minute later succeeds.

The hourly revocation worker follows Intune's 60-minute cooldown, republishes the
CRL, and reports each result back. It downloads each revocation queue once per
issuing CA rather than once per endpoint, because Microsoft filters the queue by
issuer name: endpoints sharing a CA see the same requests, and a serial is
matched against every endpoint on that CA before it is reported back as not
found. Acknowledging a sibling endpoint's certificate as "not found" would mean
it is never revoked at all. When issuance fails after Intune has authorized a request, the
failure is reported so it appears in the Intune console rather than the device
retrying silently.

`internal/scep/intune.go` is a port of Microsoft's MIT-licensed reference library
(`github.com/microsoft/Intune-Resource-Access`, commit `446e1769`), because that
logic ships only as C# and Java. Microsoft documents the library, not the wire
protocol, so if Intune enrollments start failing after a service change, diff
against `IntuneScepValidator.cs`, `IntuneClient.cs`,
`IntuneServiceLocationProvider.cs`, and `IntuneRevocationClient.cs`.

## MDM configuration

Each MDM points at one endpoint's URL and that endpoint's CA/RA bundle, downloadable from its page. Several MDMs can share an endpoint, or each can have its own.

For Apple SCEP payloads, Jamf Pro, Kandji, and Mosyle, set the endpoint URL, RSA key size 2048 or greater, digital-signature/key-encipherment usage, and the challenge. Deploy the downloaded CA chain in the same device profile.

For Workspace ONE UEM and Ivanti Neurons, configure a generic SCEP authority with the endpoint URL and CA/RA bundle. Prefer one-time challenges; use the shared secret only when the product cannot retrieve a unique challenge.

Jamf Pro dynamic challenges use `POST /integrations/jamf/scep-challenge/<endpoint-id>`. Configure the generated username and password as HTTP Basic credentials on a Jamf Pro webhook for the `SCEPChallenge` event; the response body is the challenge string Jamf expects.

For Intune, connect the Entra tenant from the SCEP tab — a Global Administrator has to complete the consent — then deploy trusted-root plus SCEP profiles together.

Put the plain endpoint URL in the profile's **SCEP Server URLs**. Windows appends NDES's CGI name to whatever it is given, so it requests `<endpoint>/pkiclient.exe`; that path is served identically and must not be added by hand, or the device asks for `/pkiclient.exe/pkiclient.exe`. A device that receives HTML instead of a SCEP response reports it as `Failed to Initialize SCEP enrollment` with result `0x800700CE` ("the file name is too long") rather than as a 404.

## Operational notes

- An enabled endpoint blocks retirement, rotation, or deletion of its issuing CA.
- An endpoint cannot be turned on until at least one of its authentication methods is on.
- Renaming an endpoint does not change its URL, so enrolled devices are unaffected.
- Renewals must use an unrevoked certificate issued by this endpoint and are accepted only inside the renewal window.
- Identical transaction retries return the original certificate. Reusing a transaction ID with a different CSR is rejected, and a recorded success is never overwritten by a later failure.
- Subject and SAN policies are regular expressions over what the device asks for. SimpleSCEP never rewrites a CSR.
- The subject policy matches Go's rendering of the CSR subject, which names `emailAddress` by its OID (`1.2.840.113549.1.9.1=#…`) rather than as `E=`, and hex-encodes the value in whatever string type the client chose. Anchor subject policies on `CN` and police email addresses through the SAN policy instead, where the value appears in plain form.
- Certificate validity, renewal window, and extended key usages are decided by the endpoint, not by the enrolling profile. An MDM's own validity-period setting is advisory and is ignored.
- A `PKCSReq` is not required to be signed by the key in its CSR, though RFC 8894 3.2.1 says it should be. Windows signs with a throwaway `CN=SCEP Protocol Certificate` keypair it mints per attempt, so enforcing the rule rejects every Intune enrollment. Nothing is lost: a PKCS#10 request is self-signed by the key being certified, so the CSR signature is what proves possession, and a certificate issued for a key the submitter does not hold is useless to them. Renewal is stricter — its signer must be an unrevoked, unexpired certificate this endpoint issued.
- Enrollment bodies are limited to 2 MiB and enrollment responses are never cacheable.
- Logs contain endpoint, operation, timing, and errors, but never challenges, private keys, or full CSRs.
