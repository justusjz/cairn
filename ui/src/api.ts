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
export type ClassForm = Schemas["ClassForm"];
export type Tier = Schemas["TierSummary"];
export type ReplicationRemote = Schemas["RemoteSummary"];
export type BackupStatus = Schemas["BackupStatus"];
export type BackupForm = Schemas["BackupForm"];
export type RestoreStatus = Schemas["RestoreStatus"];
export type Bucket = Schemas["BucketSummary"];
export type Entry = Schemas["Entry"];
export type ObjectInfo = Schemas["ObjectInfo"];
export type User = Schemas["UserSummary"];
export type OidcProvider = Schemas["OidcProvider"];
export type CorsConfiguration = Schemas["Configuration"];
export type WebsiteConfiguration = Schemas["Website"];
export type RoutingRule = Schemas["RoutingRule"];
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
export type Template = Schemas["Template"];
export type TemplateUse = Schemas["Use"];
export type MadePolicy = Schemas["MadePolicy"];
export type PolicyCatalog = Schemas["PolicyCatalog"];
export type CatalogKey = Schemas["CatalogKey"];
export type Level = Schemas["Level"];
export type Role = Schemas["RoleSummary"];
export type Group = Schemas["GroupSummary"];
export type IdentityProvider = Schemas["IdentityProvider"];
export type PermissionSet = Schemas["PermissionSetSummary"];
export type Assignment = Schemas["AssignmentSummary"];
export type DirectoryUser = Schemas["DirectoryUserSummary"];
export type OrgAccount = Schemas["AccountSummary"];
export type DirectoryGroup = Schemas["DirectoryGroupSummary"];
export type OrganizationOverview = Schemas["OrganizationOverview"];
export type OrgUnit = Schemas["UnitSummary"];
export type Scp = Schemas["ScpSummary"];
export type Topic = Schemas["TopicSummary"];
export type TopicDetail = Schemas["TopicDetail"];
export type Subscription = Schemas["SubscriptionSummary"];
export type TableBucket = Schemas["TableBucketSummary"];
export type TableBucketDetail = Schemas["TableBucketDetail"];
export type NotificationRule = Schemas["NotificationRule"];
export type Inventory = Schemas["Inventory"];
export type InventoryForm = Schemas["InventoryForm"];
export type UploadList = Schemas["UploadList"];
export type UploadInfo = Schemas["UploadInfo"];
export type ReplicationForm = Schemas["ReplicationForm"];
export type ReplicationRule = Schemas["ReplicationRuleForm"];
export type ReplicationBacklog = Schemas["ReplicationBacklog"];
export type QueuedReplication = Schemas["QueuedReplication"];
export type StorageClassName = Schemas["StorageClassName"];
export type DefaultEncryption = Schemas["DefaultEncryption"];
export type DefaultRetention = Schemas["DefaultRetention"];
export type AclGrant = Schemas["AclGrant"];
export type BucketLoggingForm = Schemas["BucketLoggingForm"];
export type ObjectDetails = Schemas["ObjectDetails"];
export type VersionDetails = Schemas["VersionDetails"];
export type TableMaintenance = Schemas["TableMaintenance"];
export type UnreferencedFileRemoval = Schemas["UnreferencedFileRemoval"];
export type TableSnapshotManagement = Schemas["TableSnapshotManagement"];
export type TableCompaction = Schemas["TableCompaction"];
export type BatchJob = Schemas["BatchJobSummary"];
export type BatchJobDetail = Schemas["BatchJobDetail"];
export type NewBatchJob = Schemas["NewBatchJob"];
export type BatchOperation = Schemas["BatchOperation"];
export type BatchManifest = Schemas["BatchManifest"];
export type AccessGrants = Schemas["AccessGrants"];
export type NewAccessGrant = Schemas["NewAccessGrant"];

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
/** A group's path. */
const groupPath = (group: string) => ({ path: { group } });

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
  /** An IAM user, with an access key (`accessKey`: its secret comes back
   * once) or none yet. */
  createUser: (
    name: string,
    opts: { accessKey?: boolean; policies?: string[]; groups?: string[]; path?: string; boundary?: string; tags?: Tag[] } = {},
  ) =>
    ok(
      client.POST("/users", {
        body: {
          name,
          access_key: opts.accessKey ?? false,
          policies: opts.policies ?? [],
          groups: opts.groups ?? [],
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
  policies: () => ok(client.GET("/policies")),
  /** The policy templates there are (see `src/templates.rs`). */
  templates: () => ok(client.GET("/templates")),
  /** The policy language's actions, operators and condition keys, as Cairn
   * knows them (see `src/console/policy_catalog.rs`). */
  policyCatalog: () => ok(client.GET("/policy-catalog")),
  /** What a template would make, used so: nothing is made. */
  previewTemplate: (use: TemplateUse) => ok(client.POST("/templates/preview", { body: use })),
  /** Makes a template's policies: all of them, or none. */
  useTemplate: (use: TemplateUse) => ok(client.POST("/templates", { body: use })),
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
    body: { label: string; issuer: string; client_id: string; client_secret: string | null; scopes: string | null; group_claim: string | null },
  ) => ok(client.PUT("/oidc-providers/{name}", { params: { path: { name } }, body })),
  deleteOidcProvider: (name: string) => ok(client.DELETE("/oidc-providers/{name}", { params: { path: { name } } })),
  permissionSets: () => ok(client.GET("/permission-sets")),
  createPermissionSet: (name: string, description: string, session_duration: number) =>
    ok(client.POST("/permission-sets", { body: { name, description, session_duration } })),
  updatePermissionSet: (name: string, description: string, session_duration: number) =>
    ok(client.PUT("/permission-sets/{name}", { params: { path: { name } }, body: { description, session_duration } })),
  deletePermissionSet: (name: string) => ok(client.DELETE("/permission-sets/{name}", { params: { path: { name } } })),
  permissionSetPolicy: (name: string) => ok(client.GET("/permission-sets/{name}/inline-policy", { params: { path: { name } } })),
  putPermissionSetPolicy: (name: string, document: string) =>
    ok(client.PUT("/permission-sets/{name}/inline-policy", { params: { path: { name } }, body: { document } })),
  deletePermissionSetPolicy: (name: string) =>
    ok(client.DELETE("/permission-sets/{name}/inline-policy", { params: { path: { name } } })),
  attachToPermissionSet: (name: string, arn: string) =>
    ok(client.POST("/permission-sets/{name}/attached", { params: { path: { name } }, body: { arn } })),
  detachFromPermissionSet: (name: string, arn: string) =>
    ok(client.DELETE("/permission-sets/{name}/attached", { params: { path: { name }, query: { arn } } })),
  assignments: () => ok(client.GET("/assignments")),
  assign: (permission_set: string, principal_type: "USER" | "GROUP", principal_id: string, account_id?: string) =>
    ok(client.POST("/assignments", { body: { permission_set, principal_type, principal_id, account_id } })),
  accounts: () => ok(client.GET("/accounts")),
  /** The names of the accounts the session may know of (the organization's
   * for who may list its accounts; else its own). */
  accountNames: () => ok(client.GET("/account-names")),
  createAccount: (name: string, email: string) => ok(client.POST("/accounts", { body: { name, email } })),
  closeAccount: (id: string) => ok(client.DELETE("/accounts/{id}", { params: { path: { id } } })),
  setPermissionSetBoundary: (name: string, arn: string) =>
    ok(client.PUT("/permission-sets/{name}/boundary", { params: { path: { name } }, body: { arn } })),
  deletePermissionSetBoundary: (name: string) =>
    ok(client.DELETE("/permission-sets/{name}/boundary", { params: { path: { name } } })),
  directoryGroups: () => ok(client.GET("/directory-groups")),
  unassign: (id: string) => ok(client.DELETE("/assignments/{id}", { params: { path: { id } } })),
  directoryUsers: () => ok(client.GET("/directory-users")),
  createDirectoryUser: (body: Schemas["NewDirectoryUser"]) => ok(client.POST("/directory-users", { body })),
  deleteDirectoryUser: (id: string) => ok(client.DELETE("/directory-users/{id}", { params: { path: { id } } })),
  directorySetupLink: (id: string) => ok(client.POST("/directory-users/{id}/setup-link", { params: { path: { id } } })),
  deleteDirectoryPasskeys: (id: string) => ok(client.DELETE("/directory-users/{id}/passkeys", { params: { path: { id } } })),
  updateDirectoryUser: (id: string, body: Schemas["DirectoryUserChange"]) =>
    ok(client.PUT("/directory-users/{id}", { params: { path: { id } }, body })),
  provisionPermissionSet: (name: string) => ok(client.POST("/permission-sets/{name}/provision", { params: { path: { name } } })),
  createDirectoryGroup: (name: string, description: string) =>
    ok(client.POST("/directory-groups", { body: { name, description: description || null } })),
  updateDirectoryGroup: (id: string, name: string, description: string) =>
    ok(client.PUT("/directory-groups/{id}", { params: { path: { id } }, body: { name, description: description || null } })),
  deleteDirectoryGroup: (id: string) => ok(client.DELETE("/directory-groups/{id}", { params: { path: { id } } })),
  addGroupMember: (id: string, user_id: string) =>
    ok(client.POST("/directory-groups/{id}/members", { params: { path: { id } }, body: { user_id } })),
  removeGroupMember: (id: string, membership: string) =>
    ok(client.DELETE("/directory-groups/{id}/members/{membership}", { params: { path: { id, membership } } })),
  organization: () => ok(client.GET("/organization")),
  enableScps: () => ok(client.PUT("/organization/scps")),
  disableScps: () => ok(client.DELETE("/organization/scps")),
  createUnit: (name: string, parent_id: string) => ok(client.POST("/organization/units", { body: { name, parent_id } })),
  renameUnit: (id: string, name: string) => ok(client.PUT("/organization/units/{id}", { params: { path: { id } }, body: { name } })),
  deleteUnit: (id: string) => ok(client.DELETE("/organization/units/{id}", { params: { path: { id } } })),
  moveAccount: (id: string, parent_id: string) => ok(client.PUT("/accounts/{id}/parent", { params: { path: { id } }, body: { parent_id } })),
  scp: (id: string) => ok(client.GET("/organization/policies/{id}", { params: { path: { id } } })),
  createScp: (body: Schemas["ScpChange"]) => ok(client.POST("/organization/policies", { body })),
  updateScp: (id: string, body: Schemas["ScpChange"]) => ok(client.PUT("/organization/policies/{id}", { params: { path: { id } }, body })),
  deleteScp: (id: string) => ok(client.DELETE("/organization/policies/{id}", { params: { path: { id } } })),
  attachScp: (id: string, target_id: string) =>
    ok(client.POST("/organization/policies/{id}/targets", { params: { path: { id } }, body: { target_id } })),
  detachScp: (id: string, target: string) =>
    ok(client.DELETE("/organization/policies/{id}/targets/{target}", { params: { path: { id, target } } })),
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
  groups: () => ok(client.GET("/groups")),
  createGroup: (name: string, path?: string) => ok(client.POST("/groups", { body: { name, path: path || null } })),
  /** Renames or moves a group (IAM's UpdateGroup). */
  updateGroup: (group: string, change: { name?: string; path?: string }) =>
    ok(client.PATCH("/groups/{group}", { params: groupPath(group), body: { name: change.name ?? null, path: change.path ?? null } })),
  deleteGroup: (group: string) => ok(client.DELETE("/groups/{group}", { params: groupPath(group) })),
  addToGroup: (group: string, user: string) =>
    ok(client.PUT("/groups/{group}/members/{user}", { params: { path: { group, user } } })),
  removeFromGroup: (group: string, user: string) =>
    ok(client.DELETE("/groups/{group}/members/{user}", { params: { path: { group, user } } })),
  attachToGroup: (group: string, arn: string) =>
    ok(client.POST("/groups/{group}/attached", { params: groupPath(group), body: { arn } })),
  detachFromGroup: (group: string, arn: string) =>
    ok(client.DELETE("/groups/{group}/attached", { params: { path: { group }, query: { arn } } })),
  groupPolicy: (group: string, policy: string) =>
    ok(client.GET("/groups/{group}/policies/{policy}", { params: { path: { group, policy } } })),
  putGroupPolicy: (group: string, policy: string, document: string) =>
    ok(client.PUT("/groups/{group}/policies/{policy}", { params: { path: { group, policy } }, body: { document } })),
  deleteGroupPolicy: (group: string, policy: string) =>
    ok(client.DELETE("/groups/{group}/policies/{policy}", { params: { path: { group, policy } } })),
  identityProviders: () => ok(client.GET("/identity-providers")),
  createIdentityProvider: (body: { url: string; client_ids: string[]; thumbprints: string[]; tags: Tag[] }) =>
    ok(client.POST("/identity-providers", { body })),
  updateIdentityProvider: (id: string, body: { client_ids: string[]; thumbprints: string[]; tags: Tag[] }) =>
    ok(client.PUT("/identity-providers/{id}", { params: { path: { id } }, body })),
  deleteIdentityProvider: (id: string) => ok(client.DELETE("/identity-providers/{id}", { params: { path: { id } } })),
  topics: () => ok(client.GET("/topics")),
  createTopic: (name: string, display_name = "") => ok(client.POST("/topics", { body: { name, display_name } })),
  topic: (name: string) => ok(client.GET("/topics/{name}", { params: { path: { name } } })),
  deleteTopic: (name: string) => ok(client.DELETE("/topics/{name}", { params: { path: { name } } })),
  setTopicSettings: (name: string, display_name: string, signature_version: number) =>
    ok(client.PUT("/topics/{name}/settings", { params: { path: { name } }, body: { display_name, signature_version } })),
  setTopicPolicy: (name: string, document: string) =>
    ok(client.PUT("/topics/{name}/policy", { params: { path: { name } }, body: { document } })),
  /** Sets the topic's delivery policy; an empty one removes it. */
  setTopicDeliveryPolicy: (name: string, document: string) =>
    ok(client.PUT("/topics/{name}/delivery-policy", { params: { path: { name } }, body: { document } })),
  setTopicTags: (name: string, tags: Tag[]) => ok(client.PUT("/topics/{name}/tags", { params: { path: { name } }, body: tags })),
  subscribe: (name: string, protocol: string, endpoint: string) =>
    ok(client.POST("/topics/{name}/subscriptions", { params: { path: { name } }, body: { protocol, endpoint } })),
  unsubscribe: (name: string, arn: string) =>
    ok(client.DELETE("/topics/{name}/subscriptions", { params: { path: { name }, query: { arn } } })),
  publish: (name: string, message: string, subject = "") =>
    ok(client.POST("/topics/{name}/publish", { params: { path: { name } }, body: { message, subject } })),
  tableBuckets: () => ok(client.GET("/table-buckets")),
  createTableBucket: (name: string) => ok(client.POST("/table-buckets", { body: { name } })),
  tableBucket: (name: string) => ok(client.GET("/table-buckets/{name}", { params: { path: { name } } })),
  deleteTableBucket: (name: string) => ok(client.DELETE("/table-buckets/{name}", { params: { path: { name } } })),
  /** Sets the table bucket's policy; an empty one deletes it. */
  setTableBucketPolicy: (name: string, document: string) =>
    ok(client.PUT("/table-buckets/{name}/policy", { params: { path: { name } }, body: { document } })),
  createNamespace: (bucket: string, namespace: string) =>
    ok(client.POST("/table-buckets/{name}/namespaces", { params: { path: { name: bucket } }, body: { name: namespace } })),
  deleteNamespace: (bucket: string, namespace: string) =>
    ok(client.DELETE("/table-buckets/{name}/namespaces/{namespace}", { params: { path: { name: bucket, namespace } } })),
  createTable: (bucket: string, namespace: string, table: string) =>
    ok(client.POST("/table-buckets/{name}/tables", { params: { path: { name: bucket } }, body: { namespace, name: table } })),
  deleteTable: (bucket: string, namespace: string, table: string) =>
    ok(client.DELETE("/table-buckets/{name}/tables/{namespace}/{table}", { params: { path: { name: bucket, namespace, table } } })),
  setTableBucketEncryption: (name: string, algorithm: string, kms_key_arn: string) =>
    ok(client.PUT("/table-buckets/{name}/encryption", { params: { path: { name } }, body: { algorithm, kms_key_arn } })),
  setTableBucketStorageClass: (name: string, storage_class: string) =>
    ok(client.PUT("/table-buckets/{name}/storage-class", { params: { path: { name } }, body: { storage_class } })),
  setTableBucketMaintenance: (name: string, body: UnreferencedFileRemoval) =>
    ok(client.PUT("/table-buckets/{name}/maintenance", { params: { path: { name } }, body })),
  tableMaintenance: (bucket: string, namespace: string, table: string) =>
    ok(client.GET("/table-buckets/{name}/tables/{namespace}/{table}/maintenance", { params: { path: { name: bucket, namespace, table } } })),
  setTableSnapshotManagement: (bucket: string, namespace: string, table: string, body: TableSnapshotManagement) =>
    ok(
      client.PUT("/table-buckets/{name}/tables/{namespace}/{table}/maintenance/snapshots", {
        params: { path: { name: bucket, namespace, table } },
        body,
      }),
    ),
  setTableCompaction: (bucket: string, namespace: string, table: string, body: TableCompaction) =>
    ok(
      client.PUT("/table-buckets/{name}/tables/{namespace}/{table}/maintenance/compaction", {
        params: { path: { name: bucket, namespace, table } },
        body,
      }),
    ),
  batchJobs: () => ok(client.GET("/batch-jobs")),
  batchJob: (id: string) => ok(client.GET("/batch-jobs/{id}", { params: { path: { id } } })),
  createBatchJob: (job: NewBatchJob) => ok(client.POST("/batch-jobs", { body: job })),
  setBatchJobPriority: (id: string, priority: number) =>
    ok(client.PUT("/batch-jobs/{id}/priority", { params: { path: { id } }, body: { priority } })),
  /** Confirms a job awaiting it (`Ready`), or cancels one (`Cancelled`). */
  setBatchJobStatus: (id: string, status: "Ready" | "Cancelled", reason = "") =>
    ok(client.PUT("/batch-jobs/{id}/status", { params: { path: { id } }, body: { status, reason } })),
  accessGrants: () => ok(client.GET("/access-grants")),
  createAccessGrantsInstance: () => ok(client.POST("/access-grants/instance")),
  deleteAccessGrantsInstance: () => ok(client.DELETE("/access-grants/instance")),
  createAccessGrantsLocation: (scope: string, role_arn: string) =>
    ok(client.POST("/access-grants/locations", { body: { scope, role_arn } })),
  updateAccessGrantsLocation: (id: string, role_arn: string) =>
    ok(client.PUT("/access-grants/locations/{id}", { params: { path: { id } }, body: { role_arn } })),
  deleteAccessGrantsLocation: (id: string) => ok(client.DELETE("/access-grants/locations/{id}", { params: { path: { id } } })),
  createAccessGrant: (grant: NewAccessGrant) => ok(client.POST("/access-grants/grants", { body: grant })),
  deleteAccessGrant: (id: string) => ok(client.DELETE("/access-grants/grants/{id}", { params: { path: { id } } })),
  bucketNotifications: (bucket: string) => ok(client.GET("/buckets/{bucket}/notifications", { params: bucketPath(bucket) })),
  setBucketNotifications: (bucket: string, rules: NotificationRule[]) =>
    ok(client.PUT("/buckets/{bucket}/notifications", { params: bucketPath(bucket), body: { rules, events: [] } })),
  inventories: (bucket: string) => ok(client.GET("/buckets/{bucket}/inventory", { params: bucketPath(bucket) })),
  putInventory: (bucket: string, form: InventoryForm) =>
    ok(client.PUT("/buckets/{bucket}/inventory/{id}", { params: { path: { bucket, id: form.id } }, body: form })),
  deleteInventory: (bucket: string, id: string) =>
    ok(client.DELETE("/buckets/{bucket}/inventory/{id}", { params: { path: { bucket, id } } })),
  bucketReplication: (bucket: string) => ok(client.GET("/buckets/{bucket}/replication", { params: bucketPath(bucket) })),
  setBucketReplication: (bucket: string, configuration: ReplicationForm) =>
    ok(client.PUT("/buckets/{bucket}/replication", { params: bucketPath(bucket), body: configuration })),
  deleteBucketReplication: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/replication", { params: bucketPath(bucket) })),
  /** The remotes a bucket's rules can name (names and kinds), to whom may
   * set its replication configuration. */
  bucketReplicationRemotes: (bucket: string) =>
    ok(client.GET("/buckets/{bucket}/replication/remotes", { params: bucketPath(bucket) })),
  /** What's queued of a key's versions, by destination. */
  replicationQueue: (bucket: string, key: string) =>
    ok(client.GET("/buckets/{bucket}/replication/queue", { params: { path: { bucket }, query: { key } } })),
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
  /** Defines a storage class, or changes all of it (`cairn class set`):
   * resolves to its layout in words, and what's wrong with it now. */
  putStorageClass: (name: string, body: ClassForm) =>
    ok(client.PUT("/storage-classes/{name}", { params: { path: { name } }, body })),
  deleteStorageClass: (name: string) => ok(client.DELETE("/storage-classes/{name}", { params: { path: { name } } })),
  tiers: () => ok(client.GET("/tiers")),
  addTier: (body: Schemas["NewTier"]) => ok(client.POST("/tiers", { body })),
  /** Changes a tier: what's left out stays; a secret left out is kept. */
  setTier: (name: string, body: Schemas["TierForm"]) =>
    ok(client.PUT("/tiers/{name}", { params: { path: { name } }, body })),
  deleteTier: (name: string) => ok(client.DELETE("/tiers/{name}", { params: { path: { name } } })),
  replicationRemotes: () => ok(client.GET("/replication-remotes")),
  addReplicationRemote: (body: Schemas["NewRemoteForm"]) => ok(client.POST("/replication-remotes", { body })),
  setReplicationRemote: (name: string, body: Schemas["RemoteForm"]) =>
    ok(client.PUT("/replication-remotes/{name}", { params: { path: { name } }, body })),
  deleteReplicationRemote: (name: string) =>
    ok(client.DELETE("/replication-remotes/{name}", { params: { path: { name } } })),
  /** The backup's status; `status` is null if it was never set up. */
  backup: () => ok(client.GET("/backup")),
  /** Turns the backup on, or changes it (`cairn backup enable`). */
  enableBackup: (body: BackupForm) => ok(client.PUT("/backup", { body })),
  disableBackup: () => ok(client.DELETE("/backup")),
  /** Runs a cycle within seconds, after a base if `base`. */
  runBackup: (base: boolean) => ok(client.POST("/backup/run", { body: { base } })),
  /** Writes an object from a file: in one PutObject, or, a large one, in
   * parts (a multipart upload), four at a time, saying how far it got. */
  upload: async (bucket: string, key: string, file: Blob, progress?: (sent: number) => void, storageClass?: string) => {
    if (file.size > MULTIPART_ABOVE) return uploadInParts(bucket, key, file, progress, storageClass);
    const query = new URLSearchParams({ key });
    if (storageClass) query.set("storage_class", storageClass);
    const url = `${BASE}/buckets/${encodeURIComponent(bucket)}/object?${query}`;
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
  /** A page of the bucket's incomplete multipart uploads, after the
   * upload `after_upload` of `after_key` (a page's `next`). */
  uploads: (bucket: string, after?: { after_key: string; after_upload: string }) =>
    ok(client.GET("/buckets/{bucket}/uploads", { params: { ...bucketPath(bucket), query: { ...after } } })),
  abortUpload: (bucket: string, key: string, upload: string) =>
    ok(client.DELETE("/buckets/{bucket}/uploads/{upload}", { params: { path: { bucket, upload }, query: { key } } })),
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
  bucketWebsite: (bucket: string) => ok(client.GET("/buckets/{bucket}/website", { params: bucketPath(bucket) })),
  putBucketWebsite: (bucket: string, configuration: WebsiteConfiguration) =>
    ok(client.PUT("/buckets/{bucket}/website", { params: bucketPath(bucket), body: configuration })),
  deleteBucketWebsite: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/website", { params: bucketPath(bucket) })),
  setVersioning: (bucket: string, status: "Enabled" | "Suspended") =>
    ok(client.PUT("/buckets/{bucket}/versioning", { params: bucketPath(bucket), body: { status } })),
};

/** A bucket's settings that S3 keeps as documents of their own, and what
 * an object version has besides its data (`src/console/settings.rs`). */
export const settingsApi = {
  /** The storage classes a write may name, the warmest first. */
  storageClasses: () => ok(client.GET("/storage-classes")),
  encryption: (bucket: string) => ok(client.GET("/buckets/{bucket}/encryption", { params: bucketPath(bucket) })),
  putEncryption: (bucket: string, body: DefaultEncryption) =>
    ok(client.PUT("/buckets/{bucket}/encryption", { params: bucketPath(bucket), body })),
  deleteEncryption: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/encryption", { params: bucketPath(bucket) })),
  objectLock: (bucket: string) => ok(client.GET("/buckets/{bucket}/object-lock", { params: bucketPath(bucket) })),
  putObjectLock: (bucket: string, default_retention: DefaultRetention | null) =>
    ok(client.PUT("/buckets/{bucket}/object-lock", { params: bucketPath(bucket), body: { default_retention } })),
  ownership: (bucket: string) => ok(client.GET("/buckets/{bucket}/ownership", { params: bucketPath(bucket) })),
  putOwnership: (bucket: string, ownership: string) =>
    ok(client.PUT("/buckets/{bucket}/ownership", { params: bucketPath(bucket), body: { ownership } })),
  deleteOwnership: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/ownership", { params: bucketPath(bucket) })),
  acl: (bucket: string) => ok(client.GET("/buckets/{bucket}/acl", { params: bucketPath(bucket) })),
  putAcl: (bucket: string, grants: AclGrant[]) => ok(client.PUT("/buckets/{bucket}/acl", { params: bucketPath(bucket), body: { grants } })),
  logging: (bucket: string) => ok(client.GET("/buckets/{bucket}/logging", { params: bucketPath(bucket) })),
  putLogging: (bucket: string, body: BucketLoggingForm) =>
    ok(client.PUT("/buckets/{bucket}/logging", { params: bucketPath(bucket), body })),
  deleteLogging: (bucket: string) => ok(client.DELETE("/buckets/{bucket}/logging", { params: bucketPath(bucket) })),
  versioning: (bucket: string) => ok(client.GET("/buckets/{bucket}/versioning", { params: bucketPath(bucket) })),
  objectDetails: (bucket: string, key: string) =>
    ok(client.GET("/buckets/{bucket}/object/details", { params: { ...bucketPath(bucket), query: { key } } })),
  putRetention: (
    bucket: string,
    key: string,
    version: string,
    body: { mode: string | null; retain_until: string | null; bypass_governance: boolean },
  ) => ok(client.PUT("/buckets/{bucket}/object/retention", { params: { ...bucketPath(bucket), query: { key, version } }, body })),
  putLegalHold: (bucket: string, key: string, version: string, on: boolean) =>
    ok(client.PUT("/buckets/{bucket}/object/legal-hold", { params: { ...bucketPath(bucket), query: { key, version } }, body: { on } })),
  putObjectAcl: (bucket: string, key: string, version: string, grants: AclGrant[]) =>
    ok(client.PUT("/buckets/{bucket}/object/acl", { params: { ...bucketPath(bucket), query: { key, version } }, body: { grants } })),
  /** Copies the key's current version onto itself, in another class. */
  changeStorageClass: (bucket: string, key: string, storage_class: string) =>
    ok(
      client.POST("/buckets/{bucket}/object/storage-class", {
        params: { ...bucketPath(bucket), query: { key } },
        body: { storage_class },
      }),
    ),
};

/** Files larger than this are uploaded in parts. */
const MULTIPART_ABOVE = 64 << 20;

/** A large file, as a multipart upload: parts of 64 MiB at least (more for
 * a file that would need more than 10000), four at a time. Aborted if a
 * part fails. */
async function uploadInParts(bucket: string, key: string, file: Blob, progress?: (sent: number) => void, storageClass?: string) {
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
    body: JSON.stringify({ key, content_type: file.type || "application/octet-stream", storage_class: storageClass || null }),
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
