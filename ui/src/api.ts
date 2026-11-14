import { createSignal } from "solid-js";
// The console's API for what the signed-in identity manages
// (`src/console/manage.rs`), through openapi-fetch. Its types are generated
// from `openapi.json`, the spec the API itself is built from (`npm run gen`
// writes `schema.d.ts`), so paths, parameters and responses are all checked
// against it. Times are seconds since the Unix epoch.

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
export type User = Schemas["UserSummary"];
export type ConsoleAccess = Schemas["ConsoleAccess"];
export type OidcProvider = Schemas["OidcProvider"];
export type CorsConfiguration = Schemas["Configuration"];
export type AccessKey = Schemas["AccessKey"];
export type ManagedPolicy = Schemas["PolicySummary"];
export type UserAccess = Schemas["UserAccess"];
export type Lifecycle = Schemas["Lifecycle"];
export type LifecycleBucket = Schemas["LifecycleBucket"];
export type LifecycleConfiguration = Schemas["LifecycleConfiguration"];
export type LifecycleRule = Schemas["LifecycleRule"];
export type BucketAccess = Schemas["BucketAccess"];
export type PublicAccessBlock = Schemas["Block"];
export type Tag = Schemas["Tag"];
export type Role = Schemas["RoleSummary"];
export type IdentityProvider = Schemas["IdentityProvider"];

/** Where the API is (also in the spec's `servers`). */
const BASE = "/api";

const client = createClient<paths>({
  baseUrl: BASE,
  // Marks requests as the UI's own: the API refuses changes without it, so
  // that other sites can't make them.
  headers: { "x-cairn-ui": "1" },
});

const [operatorMode, setOperatorModeSignal] = createSignal(false);

/** Whether the session's identity is an operator (its policies allow it
 * `cairn:GetCluster`): then the pages show what's the cluster's (its KMS).
 * (A signal: pages follow it.) */
export function setOperatorMode(operator: boolean) {
  setOperatorModeSignal(operator);
}

export function isOperator(): boolean {
  return operatorMode();
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
/** A user's path. */
const userPath = (user: string) => ({ path: { user } });
/** A role's path. */
const rolePath = (role: string) => ({ path: { role } });

export const api = {
  cluster: () => ok(client.GET("/cluster")),
  storage: () => ok(client.GET("/storage")),
  integrity: () => ok(client.GET("/integrity")),
  buckets: () => ok(client.GET("/buckets")),
  createBucket: (name: string, objectLock = false) =>
    ok(client.POST("/buckets", { body: { name, object_lock: objectLock } })),
  deleteBucket: (bucket: string) => ok(client.DELETE("/buckets/{bucket}", { params: bucketPath(bucket) })),
  objects: (bucket: string, prefix: string, after: string, deleted: boolean) =>
    ok(
      client.GET("/buckets/{bucket}/objects", {
        params: { ...bucketPath(bucket), query: { prefix, after, deleted } },
      }),
    ),
  object: (bucket: string, key: string) =>
    ok(client.GET("/buckets/{bucket}/object", { params: { ...bucketPath(bucket), query: { key } } })),
  users: () => ok(client.GET("/users")),
  /** A person (no access key: they sign in through a console link), or a
   * service (`accessKey`: one, named as it, whose secret comes back once). */
  createUser: (
    name: string,
    opts: { accessKey?: boolean; admin?: boolean; path?: string; boundary?: string; tags?: Tag[] } = {},
  ) =>
    ok(
      client.POST("/users", {
        body: {
          name,
          access_key: opts.accessKey ?? false,
          admin: opts.admin ?? false,
          path: opts.path || null,
          boundary: opts.boundary || null,
          tags: opts.tags ?? [],
        },
      }),
    ),
  deleteUser: (user: string) => ok(client.DELETE("/users/{user}", { params: userPath(user) })),
  /** Renames or moves a user (IAM's UpdateUser). */
  updateUser: (user: string, change: { name?: string; path?: string }) =>
    ok(client.PATCH("/users/{user}", { params: userPath(user), body: { name: change.name ?? null, path: change.path ?? null } })),
  setBoundary: (user: string, arn: string) =>
    ok(client.PUT("/users/{user}/boundary", { params: userPath(user), body: { arn } })),
  deleteBoundary: (user: string) => ok(client.DELETE("/users/{user}/boundary", { params: userPath(user) })),
  /** Sets all of a user's tags. */
  setUserTags: (user: string, tags: Tag[]) =>
    ok(client.PUT("/users/{user}/tags", { params: userPath(user), body: { tags } })),
  rotateSecret: (user: string) =>
    ok(client.POST("/users/{user}/secret", { params: userPath(user), body: {} })),
  setAdmin: (user: string, admin: boolean) =>
    ok(client.PUT("/users/{user}/admin", { params: userPath(user), body: { admin } })),
  policies: () => ok(client.GET("/policies")),
  createPolicy: (name: string, document: string, description: string, path?: string, tags: Tag[] = []) =>
    ok(client.POST("/policies", { body: { name, document, description, path: path || null, tags } })),
  policyVersions: (name: string) => ok(client.GET("/policies/{name}/versions", { params: { path: { name } } })),
  setDefaultVersion: (name: string, version: number) =>
    ok(client.PUT("/policies/{name}/default", { params: { path: { name } }, body: { version } })),
  deletePolicyVersion: (name: string, version: number) =>
    ok(client.DELETE("/policies/{name}/versions/{version}", { params: { path: { name, version } } })),
  /** Sets all of a managed policy's tags. */
  setPolicyTags: (name: string, tags: Tag[]) =>
    ok(client.PUT("/policies/{name}/tags", { params: { path: { name } }, body: { tags } })),
  updatePolicy: (name: string, change: { document?: string; description?: string }) =>
    ok(client.PUT("/policies/{name}", { params: { path: { name } }, body: change })),
  deleteManagedPolicy: (name: string) => ok(client.DELETE("/policies/{name}", { params: { path: { name } } })),
  attach: (user: string, arn: string) => ok(client.POST("/users/{user}/attached", { params: userPath(user), body: { arn } })),
  detach: (user: string, arn: string) =>
    ok(client.DELETE("/users/{user}/attached", { params: { path: { user }, query: { arn } } })),
  oidcConfig: () => ok(client.GET("/oidc-providers")),
  setOidcProvider: (
    name: string,
    body: { label: string; issuer: string; client_id: string; client_secret: string | null; scopes: string | null },
  ) => ok(client.PUT("/oidc-providers/{name}", { params: { path: { name } }, body })),
  deleteOidcProvider: (name: string) => ok(client.DELETE("/oidc-providers/{name}", { params: { path: { name } } })),
  createEnrollment: (user: string) =>
    ok(client.POST("/users/{user}/enrollment", { params: userPath(user) })),
  createKey: (user: string) => ok(client.POST("/users/{user}/keys", { params: userPath(user) })),
  setKeyActive: (user: string, key: string, active: boolean) =>
    ok(client.PUT("/users/{user}/keys/{key}", { params: { path: { user, key } }, body: { active } })),
  deleteKey: (user: string, key: string) =>
    ok(client.DELETE("/users/{user}/keys/{key}", { params: { path: { user, key } } })),
  policy: (user: string, policy: string) =>
    ok(client.GET("/users/{user}/policies/{policy}", { params: { path: { user, policy } } })),
  putPolicy: (user: string, policy: string, document: string) =>
    ok(client.PUT("/users/{user}/policies/{policy}", { params: { path: { user, policy } }, body: { document } })),
  deletePolicy: (user: string, policy: string) =>
    ok(client.DELETE("/users/{user}/policies/{policy}", { params: { path: { user, policy } } })),
  identifyUsers: () => ok(client.POST("/kms/identify")),
  roles: () => ok(client.GET("/roles")),
  createRole: (body: {
    name: string;
    trust: string;
    path?: string;
    description?: string;
    maxSessionDuration?: number;
    boundary?: string;
    tags?: Tag[];
  }) =>
    ok(
      client.POST("/roles", {
        body: {
          name: body.name,
          trust: body.trust,
          path: body.path || null,
          description: body.description ?? "",
          max_session_duration: body.maxSessionDuration ?? null,
          boundary: body.boundary || null,
          tags: body.tags ?? [],
        },
      }),
    ),
  updateRole: (role: string, change: { description?: string; maxSessionDuration?: number }) =>
    ok(
      client.PATCH("/roles/{role}", {
        params: rolePath(role),
        body: { description: change.description ?? null, max_session_duration: change.maxSessionDuration ?? null },
      }),
    ),
  deleteRole: (role: string) => ok(client.DELETE("/roles/{role}", { params: rolePath(role) })),
  setTrust: (role: string, document: string) => ok(client.PUT("/roles/{role}/trust", { params: rolePath(role), body: { document } })),
  setRoleBoundary: (role: string, arn: string) => ok(client.PUT("/roles/{role}/boundary", { params: rolePath(role), body: { arn } })),
  deleteRoleBoundary: (role: string) => ok(client.DELETE("/roles/{role}/boundary", { params: rolePath(role) })),
  setRoleTags: (role: string, tags: Tag[]) => ok(client.PUT("/roles/{role}/tags", { params: rolePath(role), body: { tags } })),
  attachToRole: (role: string, arn: string) => ok(client.POST("/roles/{role}/attached", { params: rolePath(role), body: { arn } })),
  detachFromRole: (role: string, arn: string) =>
    ok(client.DELETE("/roles/{role}/attached", { params: { path: { role }, query: { arn } } })),
  rolePolicy: (role: string, policy: string) =>
    ok(client.GET("/roles/{role}/policies/{policy}", { params: { path: { role, policy } } })),
  putRolePolicy: (role: string, policy: string, document: string) =>
    ok(client.PUT("/roles/{role}/policies/{policy}", { params: { path: { role, policy } }, body: { document } })),
  deleteRolePolicy: (role: string, policy: string) =>
    ok(client.DELETE("/roles/{role}/policies/{policy}", { params: { path: { role, policy } } })),
  /** Revokes the role's sessions issued until now (AWSRevokeOlderSessions). */
  revokeSessions: (role: string) => ok(client.POST("/roles/{role}/revoke-sessions", { params: rolePath(role) })),
  identityProviders: () => ok(client.GET("/identity-providers")),
  createIdentityProvider: (body: { url: string; client_ids: string[]; thumbprints: string[]; tags: Tag[] }) =>
    ok(client.POST("/identity-providers", { body })),
  updateIdentityProvider: (id: string, body: { client_ids: string[]; thumbprints: string[]; tags: Tag[] }) =>
    ok(client.PUT("/identity-providers/{id}", { params: { path: { id } }, body })),
  deleteIdentityProvider: (id: string) => ok(client.DELETE("/identity-providers/{id}", { params: { path: { id } } })),
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
  /** The signed-in account's public access block (S3 Control's), which
   * every one of its buckets gets too; `null` if it has none. */
  accountBlock: () => ok(client.GET("/account/public-access-block")),
  putAccountBlock: (block: PublicAccessBlock) => ok(client.PUT("/account/public-access-block", { body: block })),
  deleteAccountBlock: () => ok(client.DELETE("/account/public-access-block")),
  setLifecycleRate: (rate: number) => ok(client.PUT("/lifecycle/rate", { body: { rate } })),
  /** Sets a redundancy setting (`data-shards`, `parity-shards`,
   * `repair-after`); `null` unsets it. Resolves to what's wrong with the
   * cluster's layouts now, if anything. */
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
