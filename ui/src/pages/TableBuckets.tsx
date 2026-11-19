// S3 Tables (see `src/tables`): the account's table buckets, their
// namespaces, and their Apache Iceberg tables. Everything here is S3 Tables'
// own operations, as the signed-in identity: what its policies (and the
// table bucket's) allow. Query engines read and write the tables themselves
// (Spark, Trino, PyIceberg, …); here they're made, looked at and deleted.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type TableBucketDetail, api } from "../api";
import { DetailHead, Gone } from "../components/Iam";
import { Loading, Panel, Table, act, poll, toast } from "../components/ui";
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
            <Panel title="Settings" note="What new tables get, unless they ask for their own.">
              <div class="form-row">
                <span class="label">Encryption</span>
                <span class="mono">{b().encryption ?? "–"}</span>
              </div>
              <div class="form-row">
                <span class="label">Storage class</span>
                <span class="mono">{b().storage_class ?? "–"}</span>
              </div>
            </Panel>
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
    </Panel>
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
      <textarea
        class="mono"
        rows={12}
        aria-label="Policy"
        placeholder={`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::…:role/analyst"},"Action":["s3tables:GetTable","s3tables:GetTableMetadataLocation","s3tables:GetTableData"],"Resource":"${props.bucket.arn}/table/*"}]}`}
        value={text()}
        onInput={(e) => setText(e.currentTarget.value)}
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
