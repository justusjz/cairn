// The console's JSON API (`src/console/api.rs`), through openapi-fetch, typed
// by `console-openapi.json` (`npm run gen` writes `schema.d.ts`). The session
// is a cookie the browser sends by itself.

import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

type Schemas = components["schemas"];
export type Me = Schemas["Me"];
export type Passkey = Schemas["PasskeySummary"];
export type Identity = Schemas["IdentitySummary"];

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
  enrollLink: (token: string) => ok(client.POST("/enroll/link", { body: { token } })),
  switchTo: (account_id: string, challenge_id?: string, credential?: Assertion) =>
    ok(client.POST("/switch", { body: { account_id, challenge_id: challenge_id ?? null, credential: credential ?? null } })),
  loginOptions: () => ok(client.POST("/login/options")),
  oidcProviders: () => ok(client.GET("/oidc/providers")),
  /** Starts a sign-in at an OIDC provider: the URL to send the browser to. */
  oidcStart: (provider: string, purpose: "login" | "enroll" | "link" | "reauth", extra: { token?: string; account_id?: string } = {}) =>
    ok(
      client.POST("/oidc/{provider}/start", {
        params: { path: { provider } },
        body: { purpose, token: extra.token ?? null, account_id: extra.account_id ?? null },
      }),
    ),
  oidcUnlink: (provider: string) => ok(client.DELETE("/oidc/{provider}", { params: { path: { provider } } })),
  login: (challenge_id: string, credential: Assertion) => ok(client.POST("/login", { body: { challenge_id, credential } })),
  logout: () => ok(client.POST("/logout")),
  passkeyOptions: () => ok(client.POST("/passkeys/options")),
  addPasskey: (challenge_id: string, name: string, credential: Registration) =>
    ok(client.POST("/passkeys", { body: { challenge_id, name, credential } })),
  renamePasskey: (id: string, name: string) => ok(client.PUT("/passkeys/{id}", { ...passkeyPath(id), body: { name } })),
  deletePasskey: (id: string) => ok(client.DELETE("/passkeys/{id}", passkeyPath(id))),
};

export type Registration = Schemas["Registration"];
export type Assertion = Schemas["Assertion"];
