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
export type Bucket = Schemas["BucketSummary"];
export type Entry = Schemas["Entry"];
export type ObjectInfo = Schemas["ObjectInfo"];
export type Role = Schemas["RoleSummary"];
export type Permission = Schemas["Permission"];

/** Where the API is; also in the spec's `servers`. */
const BASE = "/_dashboard/api";

const client = createClient<paths>({
  baseUrl: BASE,
  // Marks requests as the dashboard's own: the API refuses changes without
  // it, so that other sites can't make them.
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
const rolePath = (role: string) => ({ path: { role } });

export const api = {
  cluster: () => ok(client.GET("/cluster")),
  storage: () => ok(client.GET("/storage")),
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
  createRole: (name: string, secret: string, admin: boolean) =>
    ok(client.POST("/roles", { body: { name, secret: secret || null, admin } })),
  deleteRole: (role: string) => ok(client.DELETE("/roles/{role}", { params: rolePath(role) })),
  rotateSecret: (role: string) => ok(client.POST("/roles/{role}/secret", { params: rolePath(role), body: {} })),
  setAdmin: (role: string, admin: boolean) =>
    ok(client.PUT("/roles/{role}/admin", { params: rolePath(role), body: { admin } })),
  grant: (role: string, bucket: string, permissions: Permission[]) =>
    ok(client.POST("/roles/{role}/grants", { params: rolePath(role), body: { bucket, permissions } })),
  revoke: (role: string, bucket: string, permission: Permission) =>
    ok(client.DELETE("/roles/{role}/grants", { params: { ...rolePath(role), query: { bucket, permission } } })),
};

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
