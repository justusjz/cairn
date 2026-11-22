// S3 Tables (see `src/tables`): the account's table buckets, their
// namespaces, and their Apache Iceberg tables. Everything here is S3 Tables'
// own operations, as the signed-in identity: what its policies (and the
// table bucket's) allow. Query engines read and write the tables themselves
// (Spark, Trino, PyIceberg, …); here they're made, looked at and deleted.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type TableBucketDetail, type TableMaintenance, api } from "../api";
import { DetailHead, Gone } from "../components/Iam";
import { PolicyDocumentEditor } from "../components/PolicyBuilder";
import { Badge, Loading, Panel, Table, type Tone, act, poll, toast } from "../components/ui";
import { date, pretty } from "../format";

export const tableBucketHref = (name: string) => `/table-buckets/${encodeURIComponent(name)}`;

/** An ISO 8601 time, as a date like the console's others. */
const when = (iso: string) => (iso ? date(Date.parse(iso) / 1000) : "–");

export default function TableBuckets() {
  const buckets = poll(() => api.tableBuckets(), 10000);
  const [creating, setCreating] = createSignal(false);
  return (
    <>
      <div class="page-head">
        <h1>Table buckets</h1>
        <button class="primary" onClick={() => setCreating(true)}>
          New table bucket
        </button>
      </div>
      <p class="subtle small">
        S3 Tables: table buckets of Apache Iceberg tables, in namespaces. A table's files are in its own storage, which
        query engines read and write through the S3 API; a commit swaps the table's pointer to its new metadata file.
        Tools for S3 Tables work with them too (<span class="mono">aws s3tables</span>, AWS's SDKs and its Iceberg
        catalog), at the S3 endpoint.
      </p>
      <Show when={buckets.data()} fallback={<Loading error={buckets.error()} />}>
        {(list) => (
          <Panel>
            <Table count={list().length} empty="No table buckets yet." columns={["Name", "Created"]}>
              <For each={list()}>
                {(b) => (
                  <tr>
                    <td>
                      <A class="mono" href={tableBucketHref(b.name)}>
                        {b.name}
                      </A>
                    </td>
                    <td>{when(b.created_at)}</td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={creating()}>
        <NewTableBucketDialog onClose={() => setCreating(false)} changed={buckets.refresh} />
      </Show>
    </>
  );
}

function NewTableBucketDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const navigate = useNavigate();
  const [name, setName] = createSignal("");
  const [error, setError] = createSignal<string>();
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.createTableBucket(n);
    } catch (e) {
      setError((e as Error).message);
      return;
    }
    toast(`Created table bucket ${n}`);
    props.changed();
    dialog.close();
    navigate(tableBucketHref(n));
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={create}>
        <h2>New table bucket</h2>
        <input type="text" placeholder="table-bucket-name" aria-label="Table bucket name" autocomplete="off" required value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        <p class="subtle small">3 to 63 lowercase letters, digits and hyphens. Unique in the account (not the cluster).</p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Create table bucket
          </button>
        </div>
      </form>
    </dialog>
  );
}

export function TableBucketPage() {
  const params = useParams();
  const name = () => params.name ?? "";
  const navigate = useNavigate();
  const bucket = poll(() => api.tableBucket(name()), 10000);
  const [gone, setGone] = createSignal(false);
  const remove = async () => {
    if (!confirm(`Delete table bucket "${name()}"? Only an empty one can be: delete its tables and namespaces first.`)) return;
    if (await act(() => api.deleteTableBucket(name()), `Deleted table bucket ${name()}`)) navigate("/table-buckets");
  };
  onMount(async () => {
    try {
      await api.tableBucket(name());
    } catch {
      setGone(true);
    }
  });
  return (
    <Show when={!gone()} fallback={<Gone kind="Table buckets" href="/table-buckets" name={name()} />}>
      <DetailHead kind="Table buckets" href="/table-buckets" name={name()}>
        <button class="danger" onClick={remove}>
          Delete table bucket
        </button>
      </DetailHead>
      <Show when={bucket.data()} fallback={<Loading error={bucket.error()} />}>
        {(b) => (
          <>
            <p class="subtle small mono">{b().arn}</p>
            <SettingsPanel bucket={b()} changed={bucket.refresh} />
            <BucketMaintenance bucket={b()} changed={bucket.refresh} />
            <Tables bucket={b()} changed={bucket.refresh} />
            <Namespaces bucket={b()} changed={bucket.refresh} />
            <PolicyPanel bucket={b()} changed={bucket.refresh} />
          </>
        )}
      </Show>
    </Show>
  );
}

function Tables(props: { bucket: TableBucketDetail; changed: () => void }) {
  const [namespace, setNamespace] = createSignal("");
  const [table, setTable] = createSignal("");
  const [maintaining, setMaintaining] = createSignal<{ namespace: string; name: string }>();
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const done = await act(
      () => api.createTable(props.bucket.name, namespace(), table().trim()),
      "Created the table: its first writer gives it its metadata",
    );
    if (done) {
      setTable("");
      props.changed();
    }
  };
  const remove = async (ns: string, t: string) => {
    if (!confirm(`Delete table ${ns}.${t}, and its files?`)) return;
    if (await act(() => api.deleteTable(props.bucket.name, ns, t), `Deleted table ${ns}.${t}`)) props.changed();
  };
  return (
    <Panel
      title="Tables"
      note="Apache Iceberg tables. Each has its own storage (its warehouse location), and points at its current metadata file, which a commit swaps."
    >
      <Table count={props.bucket.tables.length} empty="No tables yet." columns={["Namespace", "Table", "Metadata", "Modified", ""]}>
        <For each={props.bucket.tables}>
          {(t) => (
            <tr>
              <td class="mono">{t.namespace}</td>
              <td>
                <span class="mono">{t.name}</span>
                <Show when={t.warehouse_location}>{(w) => <div class="subtle small mono">{w()}</div>}</Show>
              </td>
              <td class="mono small">{t.metadata_location?.split("/").pop() ?? "–"}</td>
              <td>{when(t.modified_at)}</td>
              <td class="num">
                <button class="small" onClick={() => setMaintaining({ namespace: t.namespace, name: t.name })}>
                  Maintenance
                </button>{" "}
                <button class="small" onClick={() => remove(t.namespace, t.name)}>
                  Delete
                </button>
              </td>
            </tr>
          )}
        </For>
      </Table>
      <Show when={props.bucket.namespaces.length}>
        <form class="form-row" onSubmit={create}>
          <select aria-label="Namespace" required value={namespace()} onChange={(e) => setNamespace(e.currentTarget.value)}>
            <option value="">namespace…</option>
            <For each={props.bucket.namespaces}>{(n) => <option value={n.name}>{n.name}</option>}</For>
          </select>
          <input type="text" placeholder="table_name" aria-label="Table name" required value={table()} onInput={(e) => setTable(e.currentTarget.value)} />
          <button class="primary" type="submit">
            Create table
          </button>
        </form>
      </Show>
      <Show when={maintaining()}>
        {(t) => <TableMaintenanceDialog bucket={props.bucket.name} namespace={t().namespace} table={t().name} onClose={() => setMaintaining()} />}
      </Show>
    </Panel>
  );
}

/** A table bucket's encryption and storage class: what its new tables get. */
function SettingsPanel(props: { bucket: TableBucketDetail; changed: () => void }) {
  const current = () => props.bucket.encryption ?? "";
  const [algorithm, setAlgorithm] = createSignal(current().startsWith("aws:kms") ? "aws:kms" : "AES256");
  const [key, setKey] = createSignal(current().match(/\((.*)\)$/)?.[1] ?? "");
  const [storageClass, setStorageClass] = createSignal(props.bucket.storage_class ?? "STANDARD");
  const saveEncryption = async (e: SubmitEvent) => {
    e.preventDefault();
    const k = algorithm() === "aws:kms" ? key().trim() : "";
    if (await act(() => api.setTableBucketEncryption(props.bucket.name, algorithm(), k), "Saved the encryption")) props.changed();
  };
  const saveClass = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.setTableBucketStorageClass(props.bucket.name, storageClass()), "Saved the storage class")) props.changed();
  };
  return (
    <Panel title="Settings" note="What new tables get, unless they ask for their own; existing tables keep theirs.">
      <form class="form-row" onSubmit={saveEncryption}>
        <span class="label">Encryption</span>
        <select aria-label="Encryption" disabled={props.bucket.encryption == null} value={algorithm()} onChange={(e) => setAlgorithm(e.currentTarget.value)}>
          <option value="AES256">SSE-S3 (AES256)</option>
          <option value="aws:kms">SSE-KMS (aws:kms)</option>
        </select>
        <Show when={algorithm() === "aws:kms"}>
          <input type="text" placeholder="arn:aws:kms:…:key/…" aria-label="KMS key ARN" required value={key()} onInput={(e) => setKey(e.currentTarget.value)} />
        </Show>
        <button type="submit">Save encryption</button>
      </form>
      <form class="form-row" onSubmit={saveClass}>
        <span class="label">Storage class</span>
        <select aria-label="Storage class" disabled={props.bucket.storage_class == null} value={storageClass()} onChange={(e) => setStorageClass(e.currentTarget.value)}>
          <option value="STANDARD">STANDARD</option>
          <option value="INTELLIGENT_TIERING">INTELLIGENT_TIERING</option>
        </select>
        <button type="submit">Save storage class</button>
      </form>
      <p class="subtle small">Maintenance acts as Cairn, which can't open SSE-KMS files: a table with SSE-KMS isn't maintained.</p>
    </Panel>
  );
}

/** A table bucket's unreferenced file removal, which its tables share. */
function BucketMaintenance(props: { bucket: TableBucketDetail; changed: () => void }) {
  const config = () => props.bucket.unreferenced_file_removal;
  const [enabled, setEnabled] = createSignal(config()?.enabled ?? true);
  const [unreferenced, setUnreferenced] = createSignal(config()?.unreferenced_days ?? 3);
  const [noncurrent, setNoncurrent] = createSignal(config()?.non_current_days ?? 10);
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { enabled: enabled(), unreferenced_days: unreferenced(), non_current_days: noncurrent() };
    if (await act(() => api.setTableBucketMaintenance(props.bucket.name, body), "Saved unreferenced file removal")) props.changed();
  };
  return (
    <Panel
      title="Unreferenced file removal"
      note="Daily, for each table: files of its storage that nothing references (no snapshot, metadata or statistics file) become noncurrent, then are deleted."
    >
      <Show when={config()} fallback={<p class="subtle">You may not see it (s3tables:GetTableBucketMaintenanceConfiguration).</p>}>
        <form class="form-row" onSubmit={save}>
          <label class="check">
            <input type="checkbox" checked={enabled()} onChange={(e) => setEnabled(e.currentTarget.checked)} />
            Enabled
          </label>
          <span class="label">Noncurrent after</span>
          <input type="number" min="1" aria-label="Unreferenced days" value={unreferenced()} onInput={(e) => setUnreferenced(e.currentTarget.valueAsNumber || 0)} />
          <span class="subtle">days unreferenced, deleted</span>
          <input type="number" min="1" aria-label="Noncurrent days" value={noncurrent()} onInput={(e) => setNoncurrent(e.currentTarget.valueAsNumber || 0)} />
          <span class="subtle">days after that</span>
          <button type="submit">Save</button>
        </form>
      </Show>
    </Panel>
  );
}

const JOB_NAMES: Record<string, string> = {
  icebergCompaction: "Compaction",
  icebergSnapshotManagement: "Snapshot management",
  icebergUnreferencedFileRemoval: "Unreferenced file removal",
};

function jobTone(status: string): Tone {
  if (status === "Successful") return "ok";
  if (status === "Failed") return "bad";
  return "";
}

/** A table's snapshot management and compaction, and how its maintenance
 * jobs last went. */
function TableMaintenanceDialog(props: { bucket: string; namespace: string; table: string; onClose: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const maintenance = poll(() => api.tableMaintenance(props.bucket, props.namespace, props.table), 10000);
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <h2>
        Maintenance of <span class="mono">{`${props.namespace}.${props.table}`}</span>
      </h2>
      <Show when={maintenance.data()} fallback={<Loading error={maintenance.error()} />}>
        {(m) => <MaintenanceForms bucket={props.bucket} namespace={props.namespace} table={props.table} maintenance={m()} changed={maintenance.refresh} />}
      </Show>
      <div class="buttons">
        <button type="button" onClick={() => dialog.close()}>
          Done
        </button>
      </div>
    </dialog>
  );
}

function MaintenanceForms(props: { bucket: string; namespace: string; table: string; maintenance: TableMaintenance; changed: () => void }) {
  const snapshots = props.maintenance.snapshot_management;
  const compaction = props.maintenance.compaction;
  const [snapshotsOn, setSnapshotsOn] = createSignal(snapshots?.enabled ?? true);
  const [keep, setKeep] = createSignal(snapshots?.min_snapshots_to_keep ?? 1);
  const [age, setAge] = createSignal(snapshots?.max_snapshot_age_hours ?? 120);
  const [compactionOn, setCompactionOn] = createSignal(compaction?.enabled ?? true);
  const [size, setSize] = createSignal(compaction?.target_file_size_mb ?? 512);
  const [strategy, setStrategy] = createSignal(compaction?.strategy ?? "auto");
  const saveSnapshots = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { enabled: snapshotsOn(), min_snapshots_to_keep: keep(), max_snapshot_age_hours: age() };
    if (await act(() => api.setTableSnapshotManagement(props.bucket, props.namespace, props.table, body), "Saved snapshot management")) props.changed();
  };
  const saveCompaction = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { enabled: compactionOn(), target_file_size_mb: size(), strategy: strategy() };
    if (await act(() => api.setTableCompaction(props.bucket, props.namespace, props.table, body), "Saved compaction")) props.changed();
  };
  return (
    <>
      <Show when={snapshots && compaction} fallback={<p class="subtle">You may not see its configuration (s3tables:GetTableMaintenanceConfiguration).</p>}>
        <h3>Snapshot management</h3>
        <p class="subtle small">Hourly: snapshots beyond the newest to keep, and older than the age, expire.</p>
        <form class="form-row" onSubmit={saveSnapshots}>
          <label class="check">
            <input type="checkbox" checked={snapshotsOn()} onChange={(e) => setSnapshotsOn(e.currentTarget.checked)} />
            Enabled
          </label>
          <span class="label">Keep at least</span>
          <input type="number" min="1" aria-label="Snapshots to keep" value={keep()} onInput={(e) => setKeep(e.currentTarget.valueAsNumber || 0)} />
          <span class="label">Expire after</span>
          <input type="number" min="1" aria-label="Maximum snapshot age in hours" value={age()} onInput={(e) => setAge(e.currentTarget.valueAsNumber || 0)} />
          <span class="subtle">hours</span>
          <button type="submit">Save</button>
        </form>
        <h3>Compaction</h3>
        <p class="subtle small">
          Hourly: small files (and those with deletes) rewritten into files of the target size. <span class="mono">sort</span> and{" "}
          <span class="mono">z-order</span> need the table's sort order; <span class="mono">auto</span> sorts if it has one.
        </p>
        <form class="form-row" onSubmit={saveCompaction}>
          <label class="check">
            <input type="checkbox" checked={compactionOn()} onChange={(e) => setCompactionOn(e.currentTarget.checked)} />
            Enabled
          </label>
          <span class="label">Target size</span>
          <input type="number" min="64" max="512" aria-label="Target file size in MB" value={size()} onInput={(e) => setSize(e.currentTarget.valueAsNumber || 0)} />
          <span class="subtle">MB</span>
          <select aria-label="Strategy" value={strategy()} onChange={(e) => setStrategy(e.currentTarget.value)}>
            <For each={["auto", "binpack", "sort", "z-order"]}>{(s) => <option value={s}>{s}</option>}</For>
          </select>
          <button type="submit">Save</button>
        </form>
      </Show>
      <h3>Jobs</h3>
      <Show when={props.maintenance.jobs} fallback={<p class="subtle">You may not see them (s3tables:GetTableMaintenanceJobStatus).</p>}>
        {(jobs) => (
          <Table count={jobs().length} columns={["Job", "Status", "Last run", "Failure"]}>
            <For each={jobs()}>
              {(j) => (
                <tr>
                  <td>{JOB_NAMES[j.kind] ?? j.kind}</td>
                  <td>
                    <Badge tone={jobTone(j.status)}>{j.status.replace(/_/g, " ")}</Badge>
                  </td>
                  <td>{when(j.last_run ?? "")}</td>
                  <td class="small">{j.failure ?? ""}</td>
                </tr>
              )}
            </For>
          </Table>
        )}
      </Show>
    </>
  );
}

function Namespaces(props: { bucket: TableBucketDetail; changed: () => void }) {
  const [name, setName] = createSignal("");
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.createNamespace(props.bucket.name, name().trim()), "Created the namespace")) {
      setName("");
      props.changed();
    }
  };
  const remove = async (ns: string) => {
    if (!confirm(`Delete namespace ${ns}? Only an empty one can be.`)) return;
    if (await act(() => api.deleteNamespace(props.bucket.name, ns), `Deleted namespace ${ns}`)) props.changed();
  };
  return (
    <Panel title="Namespaces" note="One level of them; lowercase letters, digits and underscores.">
      <Table count={props.bucket.namespaces.length} empty="No namespaces yet." columns={["Namespace", "Created", ""]}>
        <For each={props.bucket.namespaces}>
          {(n) => (
            <tr>
              <td class="mono">{n.name}</td>
              <td>{when(n.created_at)}</td>
              <td class="num">
                <button class="small" onClick={() => remove(n.name)}>
                  Delete
                </button>
              </td>
            </tr>
          )}
        </For>
      </Table>
      <form class="form-row" onSubmit={create}>
        <input type="text" placeholder="namespace_name" aria-label="Namespace name" required value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        <button class="primary" type="submit">
          Create namespace
        </button>
      </form>
    </Panel>
  );
}

function PolicyPanel(props: { bucket: TableBucketDetail; changed: () => void }) {
  const [text, setText] = createSignal(props.bucket.policy ? pretty(props.bucket.policy) : "");
  const save = async () => {
    const done = await act(
      () => api.setTableBucketPolicy(props.bucket.name, text().trim()),
      text().trim() ? "Saved the policy" : "Deleted the policy",
    );
    if (done) props.changed();
  };
  return (
    <Panel
      title="Policy"
      note="Who may do what with the table bucket and its tables (s3tables: actions), besides their own policies. Empty: none. A policy that would make it public is refused."
    >
      <PolicyDocumentEditor
        kind="tables"
        label="Policy"
        resource={props.bucket.arn}
        emptyIsNone
        placeholder={`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::…:role/analyst"},"Action":["s3tables:GetTable","s3tables:GetTableMetadataLocation","s3tables:GetTableData"],"Resource":"${props.bucket.arn}/table/*"}]}`}
        document={text()}
        setDocument={setText}
      />
      <div class="buttons">
        <button onClick={() => setText(props.bucket.policy ? pretty(props.bucket.policy) : "")}>Discard changes</button>
        <button class="primary" onClick={save}>
          Save policy
        </button>
      </div>
    </Panel>
  );
}
