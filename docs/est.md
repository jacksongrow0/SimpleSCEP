# EST operations

An organization runs one or more RFC 7030 endpoints, each with its own base URL:

`https://your-simple-scep-host/.well-known/est/<endpoint-id>`

The four operations hang off that base — `/cacerts`, `/simpleenroll`, `/simplereenroll`, `/csrattrs` — and most clients are configured with the base alone and append the operation themselves. RFC 7030 §3.2.2 reserves a free-form label between `/.well-known/est` and the operation precisely so one server can front several CAs, which is what the endpoint ID is doing. HTTPS is required in production.

Endpoints are created from **SCEP · ACME · EST → Add endpoint** on the EST tab, which names the endpoint and binds it to an active issuing CA. The CA binding is fixed once created; the name and everything under Issuance policy can change later. Like an ACME endpoint and unlike a SCEP one, an EST endpoint mints no key material of its own — its responses are unsigned certs-only PKCS#7, so there is no registration authority certificate to manage.

Where SCEP serves MDM-managed devices and ACME serves things that renew themselves on a web-shaped schedule, EST serves network infrastructure: IPsec and VPN gateways running strongSwan, Cisco routers and switches, and IoT fleets built on libest or OpenXPKI. These enroll once at install and re-enroll unattended for years, often in a location nobody visits.

## Why your client authenticates with a password, not a certificate

This is the one place SimpleSCEP deviates from RFC 7030, and it is worth understanding before the first device is configured, because a client configured to present a certificate will be refused.

RFC 7030's primary client authentication is a **TLS client certificate**, checked during the TLS handshake. A common SimpleSCEP deployment runs behind a TLS-terminating proxy, where the handshake completes before the request reaches the application and a client certificate is unavailable. §3.2.3 permits **HTTP Basic over a server-authenticated TLS connection** as an alternative. That is what this implements.

A credential is a username and a password an administrator mints in the console — the direct analogue of SCEP's shared secret and of ACME's external account binding. It is sent on every enrollment and on every re-enrollment, for the life of the device.

Because a password is replayable in a way a PKCS#7 envelope or a JWS signature is not, **the endpoint refuses to accept one over a plaintext connection**. TLS terminates at the ingress, so the evidence is `X-Forwarded-Proto` rather than the connection itself; a request without it is answered `403` and no challenge is issued, since a `401` would invite the client to send its password over the same plaintext channel. If a credential ever does reach a plaintext request, the refusal is too late to help — it has already crossed the wire — so the server logs the endpoint and username and you should revoke and re-mint it.

The consequence lands on `/simplereenroll`, which the RFC authenticates by the certificate the client already holds. Here it is authenticated by two things together:

1. the same Basic credential, and
2. a **binding check**: the subject in the CSR must already hold a live certificate this endpoint issued, and the request must fall inside the endpoint's renewal window.

So a device cannot re-enroll a subject this endpoint has never certified, and cannot renew a year early. It is the same shape as SCEP's renewal authorization, which faces the same problem for the same reason.

The practical consequences:

- **The credential is the whole access-control story**, together with the endpoint's patterns. Treat one with no pin and a `.*` subject pattern the way you would treat a SCEP shared secret with a permissive usage list.
- **An expiring credential stops renewals, not just enrollments.** This is the opposite of ACME, where a client that has registered keeps working after its credential lapses. Set an expiry only for a bounded provisioning window; leave it blank for a fleet that must keep renewing.
- Give each population you police differently its own endpoint. Validity, the renewal window, subject and SAN patterns, and the permitted extended key usages are all per-endpoint.

## Enrollment credentials

Mint one per fleet, or per device if you provision individually, from the endpoint page.

The password is shown exactly once, when it is created. Only an argon2id verifier is stored, so it is never rendered again — not to you, not to support. If it is lost, mint another; there is no recovery path, by design.

Options when minting:

| Option             | What it does                                                                                                                                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Username           | What the client sends as the Basic username. No spaces or colons — a colon separates the two halves of a Basic credential, so one inside the username makes the pair ambiguous on the wire. Unique per endpoint, case-insensitively. |
| Label              | For your records only. Not sent to the client.                                                                                                                                                                                       |
| Pin to these names | Comma-separated exact names. A client using this credential can enroll only these, whatever the endpoint's patterns would otherwise allow. Checked against the CSR's common name, DNS names, and IP addresses.                       |
| Expires after      | Bounds how long the credential works — for enrollment **and** renewal. Read the warning above before setting one.                                                                                                                    |

**Revoking a credential stops the next enrollment and the next renewal.** Certificates it already issued are not revoked and keep working until they expire; revoke those from the certificates page if they should stop.

## Configuring a client

Every client needs three things: the base URL, the username, and the password. It also needs to trust the endpoint's root certificate — see below.

**strongSwan**

```
pki --est --url https://your-simple-scep-host --label <endpoint-id> \
    --userpass 'branch-gateways:<password>' \
    --in gw-muc-01.req --cacert simplescep-root.pem \
    --outform pem > gw-muc-01.pem
```

`--url` is the base URL only. strongSwan builds `/.well-known/est/<label>/<operation>`
itself, so the endpoint ID goes in `--label`; putting the whole path in `--url`
yields `/.well-known/est/<endpoint-id>/.well-known/est/simpleenroll` and a 404
that looks like a missing endpoint rather than a malformed request.

`--cacert` is a root you distributed, never one fetched from the endpoint —
fetching and trusting in one step trusts whatever answered. It can be repeated,
and usually has to be, because it serves two purposes at once: verifying the EST
server's TLS certificate and verifying the certificate the CA issues back. Where
those come from different roots — any deployment whose TLS certificate is
publicly issued — pass each as its own `--cacert`. strongSwan reads only the
first certificate out of a PEM file, so concatenating them into one bundle
silently drops all but the first.

strongSwan verifies the server hostname against the certificate's SANs and does
not match wildcards: a `*.example.com` certificate is refused for
`host.example.com` with `server certificate does not match`. An explicit
`DNS:host.example.com` SAN is required, though it may sit alongside a wildcard
in the same certificate.

**Cisco IOS**

```
crypto pki trustpoint SIMPLESCEP
 enrollment url https://your-simple-scep-host/.well-known/est/<endpoint-id>
 enrollment mode est
 enrollment credential BRANCH-GATEWAYS
 subject-name CN=gw-muc-01.example.internal
 revocation-check crl
 auto-enroll 80
```

`auto-enroll 80` re-enrols at 80% of lifetime. Set the endpoint's renewal window wide enough to cover it: with a 365-day validity, 80% leaves 73 days, which is the default window.

**libest**

```
estclient -e -s your-simple-scep-host -p 443 \
    --path-prefix /.well-known/est/<endpoint-id> \
    -u branch-gateways -h '<password>' \
    -o ./out --pem-output
```

**curl**, for checking an endpoint by hand:

```
# The chain, with no credentials at all:
curl -s https://your-simple-scep-host/.well-known/est/<endpoint-id>/cacerts \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -noout

# An enrollment:
openssl req -new -newkey rsa:2048 -nodes \
  -keyout gw.key -out gw.csr -subj /CN=gw-muc-01.example.internal
openssl req -in gw.csr -outform DER | base64 > gw.b64
curl -s -u branch-gateways:'<password>' \
  -H 'Content-Type: application/pkcs10' \
  --data-binary @gw.b64 \
  https://your-simple-scep-host/.well-known/est/<endpoint-id>/simpleenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs
```

### Trust comes first

`/cacerts` is the one operation that requires no credentials — §4.1.1 forbids requiring them, because a device that does not yet hold the CA cannot verify the TLS connection it would have to authenticate over. Everything else needs the client to already trust this root, or its request fails TLS verification before it reaches EST at all, and the error it reports will be about certificate verification rather than about EST, which sends people looking in the wrong place.

Distribute the root the way you distribute any internal root: to the appliance's trust store, to `/etc/ipsec.d/cacerts` for strongSwan, to the image for an IoT fleet. The issuing CA's SHA-256 fingerprint is on the endpoint page for checking what you distributed.

Fetching the chain from `/cacerts` and immediately trusting it is bootstrapping trust from nothing. It is fine for a lab and wrong for a fleet.

## Issuance policy

| Setting                       | What it does                                                                                                         |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Validity                      | 1 to 3650 days. How long each issued certificate lasts.                                                              |
| Renewal window                | 1 to 365 days. How early `/simplereenroll` starts working. A device asking sooner is told the date it may come back. |
| Subject pattern               | Regular expression the CSR's subject must match. Blank allows any.                                                   |
| SAN pattern                   | Regular expression the CSR's subject alternative names must match. Blank allows any.                                 |
| Permitted extended key usages | The ceiling on what a CSR may ask for.                                                                               |

The renewal window is the setting most likely to bite. A device with `auto-enroll 80` on a 365-day certificate asks 73 days out; a window of 30 refuses it for six weeks, and because the device retries silently, the first sign of trouble is an expired certificate. Set the window at or above whatever the fleet's renewal timer is configured for.

### What the CSR must contain

SimpleSCEP signs what the CSR asks for, reading the subject and SANs out of its DER rather than from anything the client says elsewhere. So:

- The **subject** and **SANs** are copied through, and are what the patterns are matched against. The subject is rendered the same way it appears in the enrollment log and on the certificates page.
- The **public key** must be RSA of at least 2048 bits, or EC on P-256 or P-384. Anything else is refused.
- The **signature on the CSR** must verify. This is proof of possession: without it, anyone who could read a CSR off the wire could enroll its subject with a key they hold.
- **Extended key usages** are read from an `extensionRequest`. A request asking for a subset of what the endpoint permits is issued exactly that subset — which is what lets one endpoint serve gateways that need `serverAuth` and clients that need `clientAuth` without either receiving the other's usage. A request asking for a usage the endpoint does not permit is refused rather than silently narrowed, so a mismatch surfaces in the enrollment log instead of producing a certificate that will not do what the device expects. A request asking for nothing gets `clientAuth` alone.

`/csrattrs` advertises the CA's public-key algorithm and signature algorithm, which steers a client that would otherwise default to RSA-2048 onto the curve the rest of the deployment uses. A CA with nothing to add answers `204`, which §4.5.2 requires and every client reads as "generate whatever you were going to generate".

## Renewal and revocation

Re-enrollment through `/simplereenroll` reuses the same credential and identity.

EST has no revocation operation; RFC 7030 leaves revocation to the CA. Revoke from the certificates page, which publishes to the CRL and answers OCSP for that certificate immediately.

`/serverkeygen` and `/fullcmc` are not implemented. A client that probes them gets a 404 and falls back to `/simpleenroll`, which is the behaviour every client we have tested has.

## Deleting an endpoint

Deleting removes the base URL, its credentials, and its enrollment history. Every consequence is delayed rather than immediate, which is what makes it worth being careful about:

- The base URL stops responding immediately, so every device configured with it fails its next enrollment.
- **Re-enrollment fails silently.** These devices renew on their own timer, often somewhere nobody visits. This does not surface as an alert; it surfaces as a gateway dropping tunnels months later. Repoint the devices at another endpoint first.
- Every credential is deleted, so devices authenticating with them lose the ability to enroll and to renew.
- No certificate is revoked. Each stays valid and trusted until it expires. If they should stop working, revoke them from the certificates page _before_ deleting.

If you only want to stop new enrollments, turn the endpoint off instead. That is reversible, leaves the credentials intact, and takes the endpoint out of the client path entirely — a disabled endpoint answers `404`, the same as one that never existed.

## Operational notes

- Administration requires an administrator role. The credential-minting route also accepts `application/json` (`{"username": …, "label": …, "identifiers": …, "ttl_hours": …}`) and returns the base URL, username, and password, for provisioning from a script. Automation should use a dedicated administrator session until service-account authentication is added.
- Failures are a plain HTTP status and a sentence, which is what §4.2.3 asks for; EST has no problem-document format. A `401` carries `WWW-Authenticate: Basic`. Only refusals a client can act on are described — an internal fault is an opaque `500`.
- A wrong username, a wrong password, and a revoked credential all produce the same `401` with the same message, and the password verification runs even when the username is unknown, so a caller cannot use response text or timing to work out which usernames exist.
- Credentials presented over a plaintext channel are always refused, and the refusal names the peer address in the log. To confirm what a new deployment's proxies actually send, deploy with `TRUSTED_PROXY_CIDRS=none` — the log then falls back to the raw peer address — send one authenticated request with a throwaway credential, read the address out of the refusal, and set the CIDR covering it.
- Requests are rate-limited per endpoint and calling address, per process. The address is taken from `CF-Connecting-IP`, then the leftmost `X-Forwarded-For`, then the connection — behind a TLS-terminating proxy the connection address is the proxy's and is the same for every device, so keying on it alone would put a whole fleet in one bucket. Those headers are trusted only because nothing but the ingress can reach the container port. Being per-process, the limit is a courtesy rather than a control under more than one replica; the controls that matter are the credential and the endpoint policy, both of which live in the database.
- Enrollments appear in the audit log as **Certificate issued**, alongside SCEP and ACME issuance. Endpoint and credential administration appear as their own actions.
- The endpoint page's activity log records refusals as well as issuance, with the reason the device was given, so a fleet that is failing to enroll shows up in the place you would look. Only refusals from a client that authenticated are recorded — a caller that never got past the credential is rate-limited and logged, but writes nothing, so it cannot fill the table.
