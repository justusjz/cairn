// The dashboard's JSON API (`src/dashboard/api.rs`), through openapi-fetch.
// Its types are generated from `openapi.json`, the spec the API itself is
// built from (`npm run gen` writes `schema.d.ts`), so paths, parameters and
// responses are all checked against it. Times are seconds since the Unix epoch.

import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

type Schemas = components["schemas"];
export type Cluster = Schemas["Cluster"];
export type ClusterNode = Schemas["ClusterNode"];
export type NodeStats = Schemas["NodeStats"];
export type Counts = Schemas["Counts"];
export type OpCounts = Schemas["OpCounts"];
export type Event = Schemas["EventReport"];
export type Storage = Schemas["Storage"];
export type Integrity = Schemas["Integrity"];
export type Finding = Schemas["FindingInfo"];
export type LostObject = Schemas["LostObject"];
export type Bucket = Schemas["BucketSummary"];
export type Entry = Schemas["Entry"];
export type ObjectInfo = Schemas["ObjectInfo"];
export type User = Schemas["RoleSummary"];
export type Account = Schemas["AccountSummary"];
export type OidcProvider = Schemas["OidcProvider"];
export type CorsConfiguration = Schemas["Configuration"];
export type AccessKey = Schemas["AccessKey"];
export type Permission = Schemas["Permission"];
export type Lifecycle = Schemas["Lifecycle"];
export type LifecycleBucket = Schemas["LifecycleBucket"];
export type LifecycleConfiguration = Schemas["LifecycleConfiguration"];
export type LifecycleRule = Schemas["LifecycleRule"];
export type BucketAccess = Schemas["BucketAccess"];
export type PublicAccessBlock = Schemas["Block"];

/** Where the API is: the dashboard's (also in the spec's `servers`), or the
 * console's, which serves the bucket and object part of it as its user. */
let BASE = "/_dashboard/api";
let consoleMode = false;

function makeClient() {
  return createClient<paths>({
    baseUrl: BASE,
    // Marks requests as the UI's own: the API refuses changes without it,
    // so that other sites can't make them.
    headers: { "x-cairn-ui": "1" },
  });
}

let client = makeClient();

/** Has the pages talk to the console's API (as the signed-in user) rather
 * than the dashboard's; called by the console before it renders. */
export function useConsoleApi() {
  BASE = "/api";
  consoleMode = true;
  client = makeClient();
}

/** Whether the pages are the console's: then what's the operator's (the
 * cluster, its settings) isn't theirs to show, but to a superadmin. */
export function isConsole(): boolean {
  return consoleMode;
}

let operatorMode = false;

/** Whether the pages act for the operator: the dashboard's, or a console
 * session's as the operator account; the console sets it as it switches. */
export function setOperatorMode(operator: boolean) {
  operatorMode = operator;
}

export function isOperator(): boolean {
  return !consoleMode || operatorMode;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** The data of a response, or its error thrown. */
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

const bucketPath = (bucket: string) => ({ path: { bucket } });
/** A user's path, and which account's (its ID): on the dashboard, which
 * lists every account's users, it says which `role` is meant. */
const rolePath = (role: string, account?: string) => ({ path: { role }, query: { account } });

export const api = {
  cluster: () => ok(client.GET("/cluster")),
  storage: () => ok(client.GET("/storage")),
  integrity: () => ok(client.GET("/integrity")),
  buckets: () => ok(client.GET("/buckets")),
  createBucket: (name: string) => ok(client.POST("/buckets", { body: { name } })),
  deleteBucket: (bucket: string) => ok(client.DELETE("/buckets/{bucket}", { params: bucketPath(bucket) })),
  objects: (bucket: string, prefix: string, after: string, deleted: boolean) =>
    ok(
      client.GET("/buckets/{bucket}/objects", {
        params: { ...bucketPath(bucket), query: { prefix, after, deleted } },
      }),
    ),
  object: (bucket: string, key: string) =>
    ok(client.GET("/buckets/{bucket}/object", { params: { ...bucketPath(bucket), query: { key } } })),
  roles: () => ok(client.GET("/roles")),
  createRole: (name: string, secret: string, admin: boolean, account?: string) =>
    ok(client.POST("/roles", { body: { name, secret: secret || null, admin, account: account ?? null } })),
  deleteRole: (role: string, account?: string) => ok(client.DELETE("/roles/{role}", { params: rolePath(role, account) })),
  rotateSecret: (role: string, account?: string) =>
    ok(client.POST("/roles/{role}/secret", { params: rolePath(role, account), body: {} })),
  setAdmin: (role: string, admin: boolean, account?: string) =>
    ok(client.PUT("/roles/{role}/admin", { params: rolePath(role, account), body: { admin } })),
  grant: (role: string, bucket: string, permissions: Permission[], account?: string) =>
    ok(client.POST("/roles/{role}/grants", { params: rolePath(role, account), body: { bucket, permissions } })),
  oidcConfig: () => ok(client.GET("/oidc-providers")),
  setOidcProvider: (
    name: string,
    body: { label: string; issuer: string; client_id: string; client_secret: string | null; scopes: string | null },
  ) => ok(client.PUT("/oidc-providers/{name}", { params: { path: { name } }, body })),
  deleteOidcProvider: (name: string) => ok(client.DELETE("/oidc-providers/{name}", { params: { path: { name } } })),
  accounts: () => ok(client.GET("/accounts")),
  createAccount: (name: string) => ok(client.POST("/accounts", { body: { name } })),
  rootEnrollment: (account: string) =>
    ok(client.POST("/accounts/{account}/enrollment", { params: { path: { account } } })),
  createEnrollment: (role: string, account?: string) =>
    ok(client.POST("/roles/{role}/enrollment", { params: rolePath(role, account) })),
  createKey: (role: string, account?: string) => ok(client.POST("/roles/{role}/keys", { params: rolePath(role, account) })),
  setKeyActive: (role: string, key: string, active: boolean, account?: string) =>
    ok(client.PUT("/roles/{role}/keys/{key}", { params: { path: { role, key }, query: { account } }, body: { active } })),
  deleteKey: (role: string, key: string, account?: string) =>
    ok(client.DELETE("/roles/{role}/keys/{key}", { params: { path: { role, key }, query: { account } } })),
  policy: (role: string, policy: string, account?: string) =>
    ok(client.GET("/roles/{role}/policies/{policy}", { params: { path: { role, policy }, query: { account } } })),
  putPolicy: (role: string, policy: string, document: string, account?: string) =>
    ok(client.PUT("/roles/{role}/policies/{policy}", { params: { path: { role, policy }, query: { account } }, body: { document } })),
  deletePolicy: (role: string, policy: string, account?: string) =>
    ok(client.DELETE("/roles/{role}/policies/{policy}", { params: { path: { role, policy }, query: { account } } })),
  identifyRoles: () => ok(client.POST("/kms/identify")),
  lifecycle: () => ok(client.GET("/lifecycle")),
  bucketLifecycle: (bucket: string) => ok(client.GET("/buckets/{bucket}/lifecycle", { params: bucketPath(bucket) })),
  setBucketLifecycle: (bucket: string, configuration: LifecycleConfiguration) =>
    ok(client.PUT("/buckets/{bucket}/lifecycle", { params: bucketPath(bucket), body: configuration })),
  deleteBucketLifecycle: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/lifecycle", { params: bucketPath(bucket) })),
  bucketAccess: (bucket: string) => ok(client.GET("/buckets/{bucket}/access", { params: bucketPath(bucket) })),
  putBucketPolicy: (bucket: string, document: string) =>
    ok(client.PUT("/buckets/{bucket}/policy", { params: bucketPath(bucket), body: { document } })),
  deleteBucketPolicy: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/policy", { params: bucketPath(bucket) })),
  putPublicAccessBlock: (bucket: string, block: PublicAccessBlock) =>
    ok(client.PUT("/buckets/{bucket}/public-access-block", { params: bucketPath(bucket), body: block })),
  deletePublicAccessBlock: (bucket: string) =>
    ok(client.DELETE("/buckets/{bucket}/public-access-block", { params: bucketPath(bucket) })),
  /** The cluster's public access block (`block-public-policy`,
   * `restrict-public-buckets`), set with `setSetting`. */
  publicAccess: () => ok(client.GET("/public-access")),
  setLifecycleRate: (rate: number) => ok(client.PUT("/lifecycle/rate", { body: { rate } })),
  /** Sets a redundancy setting (`data-shards`, `parity-shards`,
   * `repair-after`) or a public access one (`block-public-policy`,
   * `restrict-public-buckets`); `null` unsets it. Resolves to what's wrong
   * with the cluster's layouts now, if anything. */
  setSetting: (name: string, value: number | null) =>
    ok(client.PUT("/settings/{name}", { params: { path: { name } }, body: { value } })),
  removeNode: (id: number) => ok(client.POST("/nodes/{id}/remove", { params: { path: { id } } })),
  keepNode: (id: number) => ok(client.POST("/nodes/{id}/keep", { params: { path: { id } } })),
  /** Writes an object from a file: in one PutObject, or, a large one, in
   * parts (a multipart upload), four at a time, saying how far it got. */
  upload: async (bucket: string, key: string, file: Blob, progress?: (sent: number) => void) => {
    if (file.size > MULTIPART_ABOVE) return uploadInParts(bucket, key, file, progress);
    const url = `${BASE}/buckets/${encodeURIComponent(bucket)}/object?key=${encodeURIComponent(key)}`;
    const response = await fetch(url, {
      method: "PUT",
      headers: { "x-cairn-ui": "1", "content-type": file.type || "application/octet-stream" },
      body: file,
    });
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as { error?: string };
      throw new ApiError(response.status, body.error ?? `upload failed (${response.status})`);
    }
  },
  deleteObject: (bucket: string, key: string, version?: string) =>
    ok(client.DELETE("/buckets/{bucket}/object", { params: { ...bucketPath(bucket), query: { key, version } } })),
  setBucketTags: (bucket: string, tags: { key: string; value: string }[]) =>
    ok(client.PUT("/buckets/{bucket}/tags", { params: bucketPath(bucket), body: { tags } })),
  setObjectTags: (bucket: string, key: string, version: string | undefined, tags: { key: string; value: string }[]) =>
    ok(client.PUT("/buckets/{bucket}/object/tags", { params: { ...bucketPath(bucket), query: { key, version } }, body: { tags } })),
  bucketCors: (bucket: string) => ok(client.GET("/buckets/{bucket}/cors", { params: bucketPath(bucket) })),
  putBucketCors: (bucket: string, configuration: CorsConfiguration) =>
    ok(client.PUT("/buckets/{bucket}/cors", { params: bucketPath(bucket), body: configuration })),
  deleteBucketCors: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/cors", { params: bucketPath(bucket) })),
  setVersioning: (bucket: string, status: "Enabled" | "Suspended") =>
    ok(client.PUT("/buckets/{bucket}/versioning", { params: bucketPath(bucket), body: { status } })),
  revoke: (role: string, bucket: string, permission: Permission, account?: string) =>
    ok(client.DELETE("/roles/{role}/grants", { params: { path: { role }, query: { bucket, permission, account } } })),
};

/** Files larger than this are uploaded in parts. */
const MULTIPART_ABOVE = 64 << 20;

/** A large file, as a multipart upload: parts of 64 MiB at least (more for
 * a file that would need more than 10000), four at a time. Aborted if a
 * part fails. */
async function uploadInParts(bucket: string, key: string, file: Blob, progress?: (sent: number) => void) {
  const b = encodeURIComponent(bucket);
  const k = encodeURIComponent(key);
  const fail = async (response: Response) => {
    const body = (await response.json().catch(() => ({}))) as { error?: string };
    return new ApiError(response.status, body.error ?? `upload failed (${response.status})`);
  };
  const headers = { "x-cairn-ui": "1", "content-type": "application/json" };
  const started = await fetch(`${BASE}/buckets/${b}/uploads`, {
    method: "POST",
    headers,
    body: JSON.stringify({ key, content_type: file.type || "application/octet-stream" }),
  });
  if (!started.ok) throw await fail(started);
  const { upload_id: id } = (await started.json()) as { upload_id: string };
  const mib = 1 << 20;
  const size = Math.max(MULTIPART_ABOVE, Math.ceil(file.size / 10000 / mib) * mib);
  const count = Math.ceil(file.size / size);
  const etags: string[] = new Array(count);
  let next = 0;
  let sent = 0;
  try {
    const worker = async () => {
      while (next < count) {
        const i = next++;
        const part = file.slice(i * size, Math.min(file.size, (i + 1) * size));
        const response = await fetch(`${BASE}/buckets/${b}/uploads/${id}/parts/${i + 1}?key=${k}`, {
          method: "PUT",
          headers: { "x-cairn-ui": "1", "content-type": "application/octet-stream" },
          body: part,
        });
        if (!response.ok) throw await fail(response);
        etags[i] = ((await response.json()) as { etag: string }).etag;
        sent += part.size;
        progress?.(sent);
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, count) }, worker));
    const parts = etags.map((etag, i) => ({ number: i + 1, etag }));
    const done = await fetch(`${BASE}/buckets/${b}/uploads/${id}/complete?key=${k}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ parts }),
    });
    if (!done.ok) throw await fail(done);
  } catch (e) {
    await fetch(`${BASE}/buckets/${b}/uploads/${id}?key=${k}`, { method: "DELETE", headers }).catch(() => {});
    throw e;
  }
}

/** Where to download a version of an object from. It's a plain link, so the
 * browser saves the file itself. */
export function downloadUrl(bucket: string, key: string, version?: string): string {
  const query = new URLSearchParams({ key });
  if (version) query.set("version", version);
  return `${BASE}/buckets/${encodeURIComponent(bucket)}/download?${query}`;
}

/** The stats of a node that reported them. */
export function statsOf(node: ClusterNode): NodeStats | null {
  return node.stats ?? null;
}

/** A node's disk, if it reported one. */
export function diskOf(node: ClusterNode): { total: number; available: number } | null {
  const disk = node.stats?.disk;
  return disk && disk.total ? disk : null;
}

/** Why a live node's stats are missing, if they are. */
export function statsError(node: ClusterNode): string | null {
  return node.stats_error ?? null;
}
