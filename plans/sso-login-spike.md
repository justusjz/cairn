# Spike: `aws sso login` against Cairn

> Implemented in `src/console/portal.rs` (see the README's "The AWS CLI and
> SDKs"), as below: at the console's URL, with the start URL redirecting to
> `https://identitycenter.amazonaws.com/cairn/<console host>`, which is
> AWS's own issuer host rather than a customer portal's. Checked end to end
> with AWS CLI 2.41.2 (both flows, through a person allowing them in
> Chromium), and boto3, the JS SDK and the Go SDK refreshing from its cache.

Can AWS's clients be pointed at Cairn for Identity Center's access portal
APIs, **sso-oidc** (log in: register a client, device code or authorization
code with PKCE, refresh tokens) and **sso** (the portal: accounts, roles,
`GetRoleCredentials`, logout)? These were tested against a stub server that
logs every request, in November 2026.

Clients: AWS CLI 2.41.2 (installed from source with pip), botocore 1.44.7,
JS SDK v3 3.1173, Go SDK v2 (config 1.33.21, sso 1.39.5), and
aws-sdk-go-base v2.0.0-beta.76, which is what terraform-provider-aws builds
its credentials with. Terraform itself wasn't run.

## Results

Two things were tested: logging in (`aws sso login`), and getting
credentials, which an SDK does from a cached token. That means
`CreateToken` with the `refresh_token` grant once the token has expired,
then `GetRoleCredentials`.

| Override | CLI login | CLI creds | boto3 | JS v3 | Go v2 | Terraform |
| --- | --- | --- | --- | --- | --- | --- |
| `AWS_ENDPOINT_URL_SSO` + `AWS_ENDPOINT_URL_SSO_OIDC` | ✅¹ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `AWS_ENDPOINT_URL` (global) | ✅¹ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `services` section of the profile | ✅¹ | ✅ | ✅ | ❌ | ✅ | ✅ |
| `endpoint_url` in the profile | ✅¹ | ✅ | ✅ | ❌ | ❌ | – |
| Terraform's `endpoints { sso }` | | | | | | sso only, not sso-oidc² |

¹ Only with an AWS-owned start URL; see below.
² A token that needs refreshing then goes to AWS.

The one setup that works with every client: **both environment variables**
(or a `services` section, except in JS). Without the sso-oidc override, a
token refresh goes to AWS. All requests are unsigned (sso-oidc's carry
client credentials in the body, sso's the token in `x-amz-sso_bearer_token`).

### The start URL must be AWS's (CLI ≥ 2.35.13)

Since 2.35.13 ("vanity URLs"), `aws sso login` resolves `sso_start_url`
first (`awscli/customizations/sso/resolve.py`). If its host is an AWS-owned
domain (`*.awsapps.com`, `*.app.aws`, `identitycenter.amazonaws.com`, …),
it's used as is, **without any request**. Otherwise the CLI sends a `HEAD`
(then `GET`), follows at most one redirect, and fails unless it lands on an
AWS-owned domain. There's no way to turn this off. So a start URL on
Cairn's own host is refused ("Could not resolve start URL … to an AWS-owned
endpoint").

Apart from that check, the start URL is only an identifier: the token
cache's key, `startUrl` in `StartDeviceAuthorization`, and `issuerUrl` in
`RegisterClient`. The SDKs never check it. An AWS-owned URL is never
fetched, so no certificate for it is ever needed. Two ways past the check:

1. **Cairn's own start URL, redirecting (recommended).** Users configure
   `sso_start_url = https://console.example.com/start`. Cairn answers its
   `HEAD` (or `GET`) with a redirect to an AWS-shaped URL, e.g.
   `https://<anything>.awsapps.com/start`. The CLI takes the `Location`
   without fetching it (it follows one hop and stops there). Tested with a
   real HTTPS server: 301, 302, 307 and 308 work, as does a 405 on `HEAD`
   followed by a redirect on `GET`. Two hops, or a 200, are refused. Both
   login flows, and legacy profiles (no `sso-session`), then worked, with
   credentials from the CLI, boto3, JS and Go afterwards. The `awsapps.com`
   host was never contacted. What Cairn sees: the **resolved** URL, as
   `startUrl` (device flow) and `issuerUrl` (PKCE). The token cache keeps
   the **configured** one. `sso_region` is still needed unless the target
   names a region (`<id>.portal.<region>.app.aws`, which the CLI would then
   write into the config; untested).
2. **An AWS-shaped start URL in the config.** Also works, but users type
   a hostname AWS owns, which is confusing.

Either way, the AWS-owned hostname should be one AWS can't hand to a real
customer. With (1), it only appears in Cairn's redirect, and Cairn can
check for it in `RegisterClient` and `StartDeviceAuthorization`. Also worth
filing an aws-cli issue for a way to skip the check when sso-oidc's
endpoint is overridden.

### PKCE's `/authorize` ignores the endpoint's path

The CLI learns sso-oidc's resolved endpoint (with a throwaway
`RegisterClient`), then opens `<scheme>://<host>/authorize?…`, keeping only
the scheme and host. The SDKs keep a path prefix
(`AWS_ENDPOINT_URL_SSO_OIDC=https://host/sso-oidc` → `/sso-oidc/token`), but
`/authorize` is always at the host's root.

## What the clients send

```
POST /client/register        {"clientName": "botocore-client-<session>", "clientType": "public", "scopes": [...]}
                             PKCE adds: "grantTypes": ["authorization_code", "refresh_token"],
                             "redirectUris": ["http://127.0.0.1/oauth/callback"], "issuerUrl": <start URL>
POST /device_authorization   {"clientId", "clientSecret", "startUrl"}
POST /token                  {"grantType": "urn:ietf:params:oauth:grant-type:device_code", "clientId", "clientSecret", "deviceCode"}
                             {"grantType": "authorization_code", ..., "redirectUri": "http://127.0.0.1:<port>/oauth/callback", "codeVerifier", "code"}
                             {"grantType": "refresh_token", "clientId", "clientSecret", "refreshToken"}
GET  /authorize?response_type&client_id&redirect_uri&state&code_challenge&code_challenge_method=S256&scopes   (browser)
GET  /federation/credentials?account_id&role_name           x-amz-sso_bearer_token
GET  /assignment/accounts, /assignment/roles?account_id     x-amz-sso_bearer_token
POST /logout                                                x-amz-sso_bearer_token
```

The registered redirect URI has no port, and the token request's has
one: `/authorize` and `CreateToken` must accept any loopback port
(RFC 8252), as AWS does. `--use-device-code` (and legacy profiles without
an `sso-session`) use the device flow; everything else uses PKCE.

## Consequences for the design

- **Serve both APIs on the console's listener**, not the S3 endpoint:
  `/authorize` and the device page must be where people sign in anyway, the
  host's root is free there (unlike S3's, where `POST /client/register` is a
  path-style bucket `client`), and the requests are unsigned, unlike every
  other API on the S3 endpoint. Users then set
  `AWS_ENDPOINT_URL_SSO{,_OIDC}=https://console.example.com`.
- `sso_region` is then only a label, but it must be set (any region).
- Implement the refresh-token grant from the start: every SDK uses it,
  and only it, after the first hour.
- Serve `/start` on the console's host as the redirect above (a browser's
  `GET` there can go on to the sign-in page instead, by `Accept`).
- Docs: a `~/.aws/config` example with `sso-session`, the console's
  `/start` URL, and a `services` section, plus the environment variables for JS and
  for Go/Terraform, which ignore the global `AWS_ENDPOINT_URL` here.
