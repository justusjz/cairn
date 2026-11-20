// A bucket's replication configuration, to read and edit: the rules S3's
// PutBucketReplication sets (see `src/replication/config.rs`), in a form of
// the console's, which the server checks as it checks S3's; what's queued for
// each destination; and, for the object page, each version's replication
// status and what's queued of it.

import { A, useParams } from "@solidjs/router";
import { For, Show, createEffect, createSignal, on, onMount } from "solid-js";
import { type QueuedReplication, type ReplicationBacklog, type ReplicationRule, api } from "../api";
import { Badge, Loading, Panel, Table, act } from "../components/ui";
import { ago, date, num } from "../format";
import { bucketUrl } from "./Buckets";

/** A rule as the form holds it: numbers as typed. */
type Draft = {
  id: string;
  priority: string;
  enabled: boolean;
  /** Of S3's first schema: a prefix of its own, no priority or tags, and it
   * replicates delete markers. Kept as it is. */
  legacy: boolean;
  prefix: string;
  tags: { key: string; value: string }[];
  deleteMarkers: boolean;
  deleteVersions: boolean;
  kmsObjects: boolean;
  kmsKey: string;
  /** `ReplicaModifications`, kept as it was given (it has no effect). */
  replicaModifications: boolean | null;
  /** Where to: a bucket of this cluster, or of a registered remote. */
  where: "local" | "remote";
  bucket: string;
  remote: string;
  /** The ARN a remote bucket was named by (MinIO's form, say), kept. */
  arn: string | null;
  account: string;
  storageClass: string;
  ownerOverride: boolean;
};

function fromRule(r: ReplicationRule): Draft {
  const d = r.destination;
  return {
    id: r.id ?? "",
    priority: r.priority == null ? "" : String(r.priority),
    enabled: r.enabled,
    legacy: r.legacy ?? false,
    prefix: r.prefix ?? "",
    tags: (r.tags ?? []).map((t) => ({ ...t })),
    deleteMarkers: r.delete_markers ?? false,
    deleteVersions: r.delete_versions ?? false,
    kmsObjects: r.kms_objects ?? false,
    kmsKey: d.kms_key ?? "",
    replicaModifications: r.replica_modifications ?? null,
    where: d.remote ? "remote" : "local",
    bucket: d.bucket,
    remote: d.remote ?? "",
    arn: d.arn ?? null,
    account: d.account ?? "",
    storageClass: d.storage_class ?? "",
    ownerOverride: d.owner_override ?? false,
  };
}

const blank = (priority: number): Draft => ({
  id: "",
  priority: String(priority),
  enabled: true,
  legacy: false,
  prefix: "",
  tags: [],
  deleteMarkers: true,
  deleteVersions: false,
  kmsObjects: false,
  kmsKey: "",
  replicaModifications: null,
  where: "local",
  bucket: "",
  remote: "",
  arn: null,
  account: "",
  storageClass: "",
  ownerOverride: false,
});

const orNull = (v: string) => (v.trim() ? v.trim() : null);

function toRule(d: Draft, n: number): ReplicationRule {
  const priority = d.priority.trim();
  if (!d.legacy && priority && !/^-?\d+$/.test(priority))
    throw new Error(`Rule ${n}: the priority must be a whole number.`);
  if (!d.bucket.trim()) throw new Error(`Rule ${n}: the destination bucket is missing.`);
  if (d.where === "remote" && !d.remote.trim()) throw new Error(`Rule ${n}: the remote is missing.`);
  return {
    id: d.id.trim(),
    priority: d.legacy || !priority ? null : Number(priority),
    enabled: d.enabled,
    legacy: d.legacy,
    prefix: d.prefix,
    tags: d.legacy ? [] : d.tags,
    delete_markers: d.legacy || d.deleteMarkers,
    delete_versions: d.deleteVersions,
    kms_objects: d.kmsObjects,
    replica_modifications: d.replicaModifications,
    destination: {
      bucket: d.bucket.trim(),
      remote: d.where === "remote" ? d.remote.trim() : null,
      arn: d.where === "remote" ? d.arn : null,
      account: orNull(d.account),
      storage_class: orNull(d.storageClass),
      owner_override: d.ownerOverride,
      kms_key: d.kmsObjects ? orNull(d.kmsKey) : null,
    },
  };
}

/** What a rule does, in a sentence. */
function describe(d: Draft): string {
  let which = d.prefix ? `New versions under "${d.prefix}"` : "New versions";
  if (!d.legacy && d.tags.length) which += ` tagged ${d.tags.map((t) => `${t.key}=${t.value}`).join(", ")}`;
  const to =
    d.where === "remote"
      ? `the bucket ${d.bucket.trim() || "?"} of remote ${d.remote.trim() || "?"}`
      : `the bucket ${d.bucket.trim() || "?"}`;
  const also: string[] = [];
  if (d.legacy || d.deleteMarkers) also.push("delete markers");
  if (d.deleteVersions) also.push("deletions of versions");
  if (d.kmsObjects) also.push("SSE-KMS objects");
  return (
    `${which} go to ${to}` + (also.length ? `, with ${also.join(", ")}` : "") + "." + (d.enabled ? "" : " (Disabled.)")
  );
}

export default function Replication() {
  const params = useParams();
  const bucket = () => params.bucket ?? "";
  const [role, setRole] = createSignal("");
  const [drafts, setDrafts] = createSignal<Draft[]>([]);
  const [backlog, setBacklog] = createSignal<ReplicationBacklog[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [stored, setStored] = createSignal(false);
  const [error, setError] = createSignal<string>();
  // The remotes rules can name: `null` if they may not be listed (then
  // they're typed).
  const [remotes, setRemotes] = createSignal<{ name: string; kind: string }[] | null>(null);
  // Roles to pick from, if the session may list them.
  const [roles, setRoles] = createSignal<string[]>([]);

  const load = async () => {
    try {
      const r = await api.bucketReplication(bucket());
      setRole(r.configuration?.role ?? "");
      setDrafts(r.configuration?.rules.map(fromRule) ?? []);
      setBacklog(r.backlog);
      setStored(r.configuration != null);
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  createEffect(on(bucket, load));
  createEffect(
    on(bucket, () =>
      api.bucketReplicationRemotes(bucket()).then(
        (r) => setRemotes(r),
        () => setRemotes(null),
      ),
    ),
  );
  onMount(() =>
    api.roles().then(
      (rs) => setRoles(rs.map((r) => r.arn)),
      () => {},
    ),
  );

  const update = (i: number, change: Partial<Draft>) =>
    setDrafts((ds) => ds.map((d, j) => (j === i ? { ...d, ...change } : d)));
  const remove = (i: number) => setDrafts((ds) => ds.filter((_, j) => j !== i));
  const add = () => {
    const top = Math.max(0, ...drafts().map((d) => Number(d.priority) || 0));
    setDrafts((ds) => [...ds, blank(top + 1)]);
  };

  const save = async () => {
    const result = await act(async () => {
      if (!role().trim()) throw new Error("The role is missing.");
      const rules = drafts().map((d, i) => toRule(d, i + 1));
      return api.setBucketReplication(bucket(), { role: role().trim(), rules });
    }, "Saved the replication configuration; new versions are replicated by it from now on");
    if (result) load();
  };
  const removeAll = async () => {
    if (
      !confirm(
        `Remove the replication configuration of "${bucket()}"? Nothing more is replicated, and what's queued fails.`,
      )
    )
      return;
    if (await act(() => api.deleteBucketReplication(bucket()), "Removed the replication configuration")) load();
  };

  return (
    <>
      <h1>
        Replication of <span class="mono">{bucket()}</span>
      </h1>
      <div class="crumbs">
        <A href="/buckets">Buckets</A>
        <span class="sep">/</span>
        <A href={bucketUrl(bucket())}>{bucket()}</A>
        <span class="sep">/</span>
        <span>replication</span>
      </div>
      <p class="subtle">
        Each new version a rule picks is copied into its destination bucket, as S3 replicates it: same key, version ID,
        last-modified time, ETag, metadata, tags and Object Lock. Within the cluster, a replica shares its source's
        bytes. A destination can also be a bucket of another cluster (Cairn, MinIO or RustFS) registered as a remote
        (cairn remote add). Versions written before a rule existed aren't replicated: a Batch Replication job does that.
      </p>
      <p class="subtle">
        This bucket and every destination must be versioned (and have Object Lock if this bucket has it), and a
        destination must exist. That's checked as the configuration is saved, a remote's bucket on its cluster, with the
        remote's credentials; what's wrong is shown as the server says it.
      </p>
      <Show when={loaded()} fallback={<Loading error={error()} />}>
        <Show when={backlog().length}>
          <Panel title="Queued for replication">
            <Table
              columns={[
                "Destination",
                { label: "Queued", num: true },
                { label: "Retrying", num: true },
                "Oldest",
                "Last failure",
              ]}
              count={backlog().length}
            >
              <For each={backlog()}>
                {(b) => (
                  <tr>
                    <td class="mono">{b.destination}</td>
                    <td class="num">{num(b.queued)}</td>
                    <td class="num">{num(b.retrying)}</td>
                    <td title={date(b.oldest)}>{ago(b.oldest)}</td>
                    <td>{b.failure ?? <span class="subtle">none</span>}</td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        </Show>
        <Panel title="Role">
          <div class="form-row">
            <span class="label">Role ARN</span>
            <input
              type="text"
              list="replication-roles"
              placeholder="arn:aws:iam::<account>:role/<name>"
              aria-label="Role ARN"
              value={role()}
              onInput={(e) => setRole(e.currentTarget.value)}
            />
            <datalist id="replication-roles">
              <For each={roles()}>{(arn) => <option value={arn} />}</For>
            </datalist>
          </div>
          <p class="subtle">
            Replication acts as this role, of the bucket's account. It must trust s3.amazonaws.com, and be allowed
            s3:GetObjectVersionForReplication on this bucket's objects and s3:ReplicateObject, s3:ReplicateDelete and
            s3:ReplicateTags on the destinations' (a remote's credentials decide what's written there). Saving needs
            iam:PassRole on it.
          </p>
        </Panel>
        <Show
          when={drafts().length}
          fallback={
            <Panel>
              {stored() ? "No rules left: remove the configuration instead." : "This bucket isn't replicated."}
            </Panel>
          }
        >
          <For each={drafts()}>
            {(d, i) => (
              <RuleEditor
                draft={d}
                n={i() + 1}
                remotes={remotes()}
                update={(c) => update(i(), c)}
                remove={() => remove(i())}
              />
            )}
          </For>
        </Show>
        <div class="toolbar">
          <button onClick={add}>Add rule</button>
          <span class="spacer" />
          <Show when={stored()}>
            <button class="danger" onClick={removeAll}>
              Remove configuration
            </button>
          </Show>
          <button onClick={load}>Discard changes</button>
          <button class="primary" disabled={!drafts().length} onClick={save}>
            Save configuration
          </button>
        </div>
      </Show>
    </>
  );
}

function RuleEditor(props: {
  draft: Draft;
  n: number;
  remotes: { name: string; kind: string }[] | null;
  update: (change: Partial<Draft>) => void;
  remove: () => void;
}) {
  const d = () => props.draft;
  const input = (key: keyof Draft, placeholder: string, label: string, width?: string) => (
    <input
      type="text"
      placeholder={placeholder}
      aria-label={label}
      style={width ? { flex: `0 1 ${width}` } : undefined}
      value={d()[key] as string}
      onInput={(e) => props.update({ [key]: e.currentTarget.value })}
    />
  );
  const check = (
    key: "enabled" | "deleteMarkers" | "deleteVersions" | "kmsObjects" | "ownerOverride",
    label: string,
    disabled = false,
  ) => (
    <label class="check">
      <input
        type="checkbox"
        checked={d()[key]}
        disabled={disabled}
        onChange={(e) => props.update({ [key]: e.currentTarget.checked })}
      />
      {label}
    </label>
  );
  // The remotes to pick from, and the rule's own if it isn't listed.
  const names = () => {
    const listed = (props.remotes ?? []).map((r) => r.name);
    return d().remote && !listed.includes(d().remote) ? [d().remote, ...listed] : listed;
  };
  return (
    <Panel
      title={
        <>
          Rule {props.n}
          <span class="subtle">{describe(d())}</span>
        </>
      }
    >
      <div class="rule">
        <div class="form-row">
          <span class="label">Name</span>
          {input("id", "made up if empty", "Rule name")}
          <Show when={!d().legacy}>
            <span class="subtle">priority</span>
            {input("priority", "0", "Priority", "90px")}
          </Show>
          {check("enabled", "Enabled")}
          <button class="small danger" onClick={props.remove}>
            Remove rule
          </button>
        </div>
        <Show when={d().legacy}>
          <div class="form-row">
            <span class="label" />
            <span class="subtle">
              A rule of S3's first schema, kept as it is: a prefix alone, no priority, and delete markers are
              replicated. Rules of the two schemas can't be in one configuration.
            </span>
          </div>
        </Show>
        <div class="form-row">
          <span class="label">Versions</span>
          {input("prefix", "key prefix (all keys if empty)", "Key prefix")}
        </div>
        <Show when={!d().legacy}>
          <For each={d().tags}>
            {(t, j) => {
              const set = (change: Partial<{ key: string; value: string }>) =>
                props.update({ tags: d().tags.map((u, k) => (k === j() ? { ...u, ...change } : u)) });
              return (
                <div class="form-row">
                  <span class="label">{j() === 0 ? "Tagged" : "and"}</span>
                  <input
                    type="text"
                    placeholder="tag key"
                    aria-label="Tag key"
                    value={t.key}
                    onInput={(e) => set({ key: e.currentTarget.value })}
                  />
                  <span>=</span>
                  <input
                    type="text"
                    placeholder="value (may be empty)"
                    aria-label="Tag value"
                    value={t.value}
                    onInput={(e) => set({ value: e.currentTarget.value })}
                  />
                  <button class="small" onClick={() => props.update({ tags: d().tags.filter((_, k) => k !== j()) })}>
                    Remove tag
                  </button>
                </div>
              );
            }}
          </For>
          <div class="form-row">
            <span class="label" />
            <button
              class="small"
              onClick={() => props.update({ tags: [...d().tags, { key: "", value: "" }], deleteMarkers: false })}
            >
              Add tag
            </button>
            <span class="subtle">
              versions must have every tag, with its value; rules with tags can't replicate delete markers
            </span>
          </div>
        </Show>
        <div class="form-row">
          <span class="label">Destination</span>
          <select value={d().where} onChange={(e) => props.update({ where: e.currentTarget.value as Draft["where"] })}>
            <option value="local">a bucket of this cluster</option>
            <option value="remote">a bucket of a remote</option>
          </select>
          <Show when={d().where === "remote"}>
            <Show
              when={names().length}
              fallback={input(
                "remote",
                props.remotes ? "remote (none registered: cairn remote add)" : "remote name",
                "Remote",
                "220px",
              )}
            >
              <select
                value={d().remote}
                aria-label="Remote"
                onChange={(e) => props.update({ remote: e.currentTarget.value })}
              >
                <Show when={!d().remote}>
                  <option value="">pick a remote</option>
                </Show>
                <For each={names()}>
                  {(name) => {
                    const kind = props.remotes?.find((r) => r.name === name)?.kind;
                    return <option value={name}>{kind ? `${name} (${kind})` : name}</option>;
                  }}
                </For>
              </select>
            </Show>
          </Show>
          {input("bucket", "bucket name", "Destination bucket", "240px")}
        </div>
        <Show when={d().where === "remote" && d().remote && d().bucket}>
          <div class="form-row">
            <span class="label" />
            <span class="subtle">
              named{" "}
              <span class="mono">{d().arn ?? `arn:cairn:replication::${d().remote.trim()}:${d().bucket.trim()}`}</span>
            </span>
          </div>
        </Show>
        <div class="form-row">
          <span class="label">Replicas</span>
          {input("storageClass", "storage class (the source's if empty)", "Storage class", "260px")}
          {input("account", "owner account ID (not checked if empty)", "Destination account", "280px")}
          {check("ownerOverride", "owned by the destination's account")}
        </div>
        <div class="form-row">
          <span class="label">Also replicate</span>
          {check("deleteMarkers", "delete markers", d().legacy || (!d().legacy && d().tags.length > 0))}
          {check("kmsObjects", "SSE-KMS objects")}
          <Show when={d().kmsObjects}>
            {input("kmsKey", "replicas' KMS key (mount/key)", "Replica KMS key", "240px")}
          </Show>
        </div>
        <div class="form-row">
          <span class="label" />
          {check("deleteVersions", "deletions of versions")}
          <span class="subtle">
            MinIO's DeleteReplication, a Cairn and MinIO extension that S3 hasn't: deleting a version by its ID deletes
            its replica too (in this cluster, while it's still a replica)
          </span>
        </div>
      </div>
    </Panel>
  );
}

/** A version's replication status (`x-amz-replication-status`), as a badge;
 * nothing if it isn't replicated. */
export function ReplicationBadge(props: { status?: string | null }) {
  const tone = () =>
    props.status === "FAILED" ? "bad" : props.status === "PENDING" ? "warn" : props.status === "COMPLETED" ? "ok" : "";
  return (
    <Show when={props.status}>
      {(s) => <Badge tone={tone()}>{s() === "REPLICA" ? "replica" : `replication ${s().toLowerCase()}`}</Badge>}
    </Show>
  );
}

/** What's queued of a key's versions, by destination, if anything is (and
 * the session may see it: it names the destinations). */
export function ReplicationQueue(props: { bucket: string; keyName: string }) {
  const [queued, setQueued] = createSignal<QueuedReplication[]>([]);
  createEffect(
    on([() => props.bucket, () => props.keyName], () =>
      api.replicationQueue(props.bucket, props.keyName).then(setQueued, () => setQueued([])),
    ),
  );
  const what = (q: QueuedReplication) => (q.purge ? "deletion" : q.marker ? "delete marker" : "version");
  return (
    <Show when={queued().length}>
      <Panel title="Queued for replication">
        <Table
          columns={[
            "Version",
            "What",
            "Destination",
            "Rule",
            { label: "Tries", num: true },
            "Next try",
            "Last failure",
          ]}
          count={queued().length}
        >
          <For each={queued()}>
            {(q) => (
              <tr>
                <td class="mono">{q.version_id}</td>
                <td>{what(q)}</td>
                <td class="mono">{q.destination}</td>
                <td>{q.rule_id}</td>
                <td class="num">{num(q.attempts)}</td>
                <td>{date(q.next_at)}</td>
                <td>{q.failure ?? <span class="subtle">none</span>}</td>
              </tr>
            )}
          </For>
        </Table>
      </Panel>
    </Show>
  );
}
