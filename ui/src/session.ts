// The console's sign-in API (`src/console/api.rs`), through openapi-fetch,
// typed by `openapi.json` (`npm run gen` writes `schema.d.ts`). The session
// is a cookie the browser sends by itself.

import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

type Schemas = components["schemas"];
export type Me = Schemas["Me"];
export type Passkey = Schemas["PasskeySummary"];
export type Identity = Schemas["IdentitySummary"];
export type DirectoryMe = Schemas["DirectoryMe"];
export type Credentials = Schemas["Credentials"];
export type SignInRequest = Schemas["SignInRequest"];

const client = createClient<paths>({
  baseUrl: "/api",
  // Marks requests as the console's own: the API refuses changes without it.
  headers: { "x-cairn-ui": "1" },
});

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function ok<T>(
  request: Promise<{ data?: T; error?: { error: string } | unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await request;
  if (error !== undefined || !response.ok) {
    const message = (error as { error?: string } | undefined)?.error;
    throw new ApiError(response.status, message ?? `request failed (${response.status})`);
  }
  return data as T;
}

const passkeyPath = (id: string) => ({ params: { path: { id } } });

export const api = {
  /** Who's signed in; an ApiError with status 401 if no one. */
  me: () => ok(client.GET("/me")),
  enrollOptions: (token: string) => ok(client.POST("/enroll/options", { body: { token } })),
  enroll: (token: string, challenge_id: string, name: string, credential: Registration) =>
    ok(client.POST("/enroll", { body: { token, challenge_id, name, credential } })),
  loginOptions: () => ok(client.POST("/login/options")),
  oidcProviders: () => ok(client.GET("/oidc/providers")),
  /** Whether anyone can sign in yet. */
  setup: () => ok(client.GET("/setup")),
  /** Starts a sign-in at an identity source, as a directory user: the URL to
   * send the browser to. */
  oidcStart: (provider: string) => ok(client.POST("/oidc/{provider}/start", { params: { path: { provider } } })),
  /** Has a directory user's session act as one of its permission sets, in
   * an account it's assigned in. */
  choosePermissionSet: (name: string, account_id: string) =>
    ok(client.POST("/directory/permission-set", { body: { name, account_id } })),
  /** Temporary credentials of a directory user's permission set, for the CLI. */
  directoryCredentials: () => ok(client.POST("/directory/credentials")),
  login: (challenge_id: string, credential: Assertion) => ok(client.POST("/login", { body: { challenge_id, credential } })),
  logout: () => ok(client.POST("/logout")),
  /** Signs in as the account's root user, with a link from `cairn account root-link`. */
  rootSignIn: (token: string) => ok(client.POST("/root/sign-in", { body: { token } })),
  passkeyOptions: () => ok(client.POST("/passkeys/options")),
  addPasskey: (challenge_id: string, name: string, credential: Registration) =>
    ok(client.POST("/passkeys", { body: { challenge_id, name, credential } })),
  renamePasskey: (id: string, name: string) => ok(client.PUT("/passkeys/{id}", { ...passkeyPath(id), body: { name } })),
  deletePasskey: (id: string) => ok(client.DELETE("/passkeys/{id}", passkeyPath(id))),
  /** Has the session act as a session of a role (by its account's ID, and
   * its name after its path), as STS's AssumeRole would let it. */
  switchRole: (account: string, role: string) => ok(client.POST("/switch-role", { body: { account, role } })),
  /** Has the session act as who it signed in as again. */
  switchBack: () => ok(client.DELETE("/switch-role")),
  /** A sign-in of the AWS CLI or an SDK in a browser, waiting for the
   * signed-in directory user to allow it. */
  signInRequest: (id: string) => ok(client.GET("/sso/requests/{id}", { params: { path: { id } } })),
  /** The device sign-in of a code a program shows. */
  deviceSignInRequest: (user_code: string) => ok(client.POST("/sso/device", { body: { user_code } })),
  /** Allows a sign-in of the AWS CLI or an SDK, as the signed-in directory
   * user, or denies it: where to send the browser on to, for a browser's. */
  decideSignIn: (id: string, allow: boolean) =>
    ok(client.POST("/sso/requests/{id}", { params: { path: { id } }, body: { allow } })),
};

export type Registration = Schemas["Registration"];
export type Assertion = Schemas["Assertion"];
