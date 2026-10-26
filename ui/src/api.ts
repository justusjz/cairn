// The dashboard's JSON API (`src/dashboard/api.rs`), and the shapes it answers
// with. Times are seconds since the Unix epoch.

export interface Counts {
  requests: number;
  client_errors: number;
  server_errors: number;
  bytes_in: number;
  bytes_out: number;
  latency_us: number;
}

export interface OpCounts extends Counts {
  op: string;
}

/** A slot of request history, starting at `t`. */
export interface Slot extends Counts {
  t: number;
}

export interface Event {
  time: number;
  source: string;
  error: boolean;
  message: string;
}

export interface Maintenance {
  interval_secs: number;
  passes: number;
  running_since: number | null;
  last_started: number | null;
  last_duration: number | null;
  sweep_shard: number;
  shards: number;
  gc: { pending: number; files: number; dirs: number; errors: number };
  packer: { jobs: number; failed: number; blobs: number; parts: number; bytes: number };
  events: Event[];
}

/** What a node reports about itself. */
export interface NodeStats {
  node: number;
  node_id: string;
  version: string;
  replication_factor: number;
  now: number;
  started_at: number;
  in_flight: number;
  disk: { total: number; available: number } | { error: string };
  requests: { slot_secs: number; ops: OpCounts[]; history: Slot[] };
  maintenance: Maintenance;
}

export interface ClusterNode {
  id: number;
  node_id: string;
  peer_url: string;
  last_seen: number;
  free_space: number;
  live: boolean;
  /** What the node reported; null if it's down. */
  stats: NodeStats | { error: string } | null;
}

export interface Cluster {
  this_node: number;
  replication_factor: number;
  now: number;
  nodes: ClusterNode[];
}

export interface Storage {
  replication_factor: number;
  nodes: { node: number; blobs: number; bytes: number }[];
  replicas: { live: number; copies: number; blobs: number; bytes: number }[];
  blobs: { committed: number; bytes: number; garbage_bytes: number; pending: number; oldest_pending: number | null };
  objects: {
    buckets: number;
    current: number;
    current_bytes: number;
    noncurrent: number;
    noncurrent_bytes: number;
    delete_markers: number;
  };
  backlog: {
    packing: number;
    packing_bytes: number;
    consolidate: number;
    consolidate_bytes: number;
    compact: number;
    compact_garbage_bytes: number;
    garbage_log: number;
    uploads: number;
    oldest_upload: number | null;
    upload_bytes: number;
  };
  packer: { target_size: number; small_size: number; compact_threshold: number; max_sources: number };
}

export interface Bucket {
  name: string;
  created_at: number;
  versioning: "unversioned" | "enabled" | "suspended";
  objects: number;
  bytes: number;
  versions: number;
  version_bytes: number;
  uploads: number;
  roles: number;
}

export type Entry =
  | { prefix: string; objects: number; bytes: number; last_modified: number }
  | { key: string; size: number; etag: string | null; last_modified: number; delete_marker: boolean };

export interface Listing {
  entries: Entry[];
  next: string | null;
}

export interface Part {
  number: number;
  size: number;
  etag: string;
  crc64nvme: string | null;
  blob_id: string;
  blob_offset: number;
  blob_size: number;
  blob_state: string;
  created_at: number;
  nodes: number[];
}

export interface Version {
  version_id: string;
  latest: boolean;
  delete_marker: boolean;
  size: number;
  etag: string | null;
  content_type: string | null;
  last_modified: number;
  parts: Part[];
}

export interface ObjectInfo {
  bucket: string;
  key: string;
  versions: Version[];
}

export type Permission = "read" | "write" | "delete-version";

export interface Role {
  name: string;
  admin: boolean;
  created_at: number;
  grants: { bucket: string; permission: Permission }[];
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  // The header marks the request as the dashboard's own: the API refuses
  // changes without it, so that other sites can't make them.
  const headers: Record<string, string> = { "x-cairn-ui": "1" };
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const res = await fetch("/api/" + path, init);
  let data: any = {};
  try {
    data = await res.json();
  } catch {
    // Not JSON: the status says enough.
  }
  if (!res.ok) throw new ApiError(res.status, data.error ?? `request failed (${res.status})`);
  return data as T;
}

const enc = encodeURIComponent;

export const api = {
  cluster: () => request<Cluster>("GET", "cluster"),
  storage: () => request<Storage>("GET", "storage"),
  buckets: () => request<{ buckets: Bucket[] }>("GET", "buckets").then((r) => r.buckets),
  createBucket: (name: string) => request("POST", "buckets", { name }),
  deleteBucket: (name: string) => request("DELETE", `buckets/${enc(name)}`),
  objects: (bucket: string, prefix: string, after: string, deleted: boolean) =>
    request<Listing>(
      "GET",
      `buckets/${enc(bucket)}/objects?prefix=${enc(prefix)}&after=${enc(after)}` + (deleted ? "&deleted=1" : ""),
    ),
  object: (bucket: string, key: string) => request<ObjectInfo>("GET", `buckets/${enc(bucket)}/object?key=${enc(key)}`),
  roles: () => request<{ roles: Role[] }>("GET", "roles").then((r) => r.roles),
  createRole: (name: string, secret: string, admin: boolean) =>
    request<{ name: string; secret: string }>("POST", "roles", { name, secret, admin }),
  deleteRole: (name: string) => request("DELETE", `roles/${enc(name)}`),
  rotateSecret: (name: string) => request<{ name: string; secret: string }>("POST", `roles/${enc(name)}/secret`, {}),
  setAdmin: (name: string, admin: boolean) => request("POST", `roles/${enc(name)}/admin`, { admin }),
  grant: (name: string, bucket: string, permissions: Permission[]) =>
    request("POST", `roles/${enc(name)}/grants`, { bucket, permissions }),
  revoke: (name: string, bucket: string, permission: Permission) =>
    request("DELETE", `roles/${enc(name)}/grants?bucket=${enc(bucket)}&permission=${enc(permission)}`),
};

/** Where to download a version of an object from. */
export function downloadUrl(bucket: string, key: string, version?: string): string {
  return `/api/buckets/${enc(bucket)}/download?key=${enc(key)}` + (version ? "&version=" + enc(version) : "");
}

/** The stats of a node that reported them. */
export function statsOf(node: ClusterNode): NodeStats | null {
  return node.stats && !("error" in node.stats) ? node.stats : null;
}

/** A node's disk, if it reported one. */
export function diskOf(node: ClusterNode): { total: number; available: number } | null {
  const disk = statsOf(node)?.disk;
  return disk && "total" in disk && disk.total ? disk : null;
}
