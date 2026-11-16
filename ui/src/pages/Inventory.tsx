// A bucket's S3 Inventory configurations (see `src/inventory`): reports of
// its objects, daily or weekly, written as CSV or Parquet files to a
// destination bucket, as S3 writes them; and how each one's reports are
// going.

import { A, useParams } from "@solidjs/router";
import { For, Show, createSignal } from "solid-js";
import { type Inventory as InventoryInfo, type InventoryForm, api } from "../api";
import { Badge, Loading, Panel, Table, act, poll } from "../components/ui";
import { ago, date, num } from "../format";
import { bucketUrl } from "./Buckets";

const blank = (bucket: string): InventoryForm => ({
  id: "",
  enabled: true,
  destination_bucket: bucket,
  destination_prefix: "",
  destination_account: null,
  format: "CSV",
  encryption: null,
  prefix: "",
  all_versions: false,
  frequency: "Daily",
  fields: ["Size", "LastModifiedDate", "ETag"],
});

/** The statement a destination bucket's policy needs, for S3 (Cairn, as
 * it) to write the reports. */
function destinationStatement(source: string, f: InventoryForm): string {
  const prefix = f.destination_prefix ? `${f.destination_prefix.replace(/\/$/, "")}/` : "";
  return JSON.stringify(
    {
      Sid: "InventoryReports",
      Effect: "Allow",
      Principal: { Service: "s3.amazonaws.com" },
      Action: "s3:PutObject",
      Resource: `arn:aws:s3:::${f.destination_bucket}/${prefix}*`,
      Condition: { ArnLike: { "aws:SourceArn": `arn:aws:s3:::${source}` } },
    },
    null,
    2,
  );
}

export default function Inventory() {
  const params = useParams();
  const bucket = () => params.bucket ?? "";
  const data = poll(() => api.inventories(bucket()), 15000);
  const [editing, setEditing] = createSignal<InventoryForm>();
  const remove = async (id: string) => {
    if (!confirm(`Delete inventory configuration "${id}"? A report of it in progress stops; its files stay.`)) return;
    if (await act(() => api.deleteInventory(bucket(), id), `Deleted ${id}`)) data.refresh();
  };
  return (
    <>
      <h1>
        Inventory of <span class="mono">{bucket()}</span>
      </h1>
      <div class="crumbs">
        <A href="/buckets">Buckets</A>
        <span class="sep">/</span>
        <A href={bucketUrl(bucket())}>{bucket()}</A>
        <span class="sep">/</span>
        <span>inventory</span>
      </div>
      <p class="subtle">
        Reports listing the bucket's objects (or all their versions), with the fields asked for, as S3 Inventory writes
        them: data files, a manifest and a Hive symlink file, in the destination bucket. Reports are made in steps,
        sharing the rate of lifecycle sweeps.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <>
            <Panel>
              <Table count={d().inventories.length} empty="No inventory configurations." columns={["Name", "Reports", "Destination", "Last report", "Now", ""]}>
                <For each={d().inventories}>{(i) => <Row info={i} edit={() => setEditing({ ...i.configuration, fields: [...(i.configuration.fields ?? [])] })} remove={() => remove(i.configuration.id)} />}</For>
              </Table>
            </Panel>
            <div class="toolbar">
              <button class="primary" onClick={() => setEditing(blank(bucket()))}>
                New configuration
              </button>
            </div>
            <Show when={editing()}>
              {(f) => <Editor bucket={bucket()} form={f()} fields={d().fields} close={() => setEditing(undefined)} saved={data.refresh} />}
            </Show>
          </>
        )}
      </Show>
    </>
  );
}

function Row(props: { info: InventoryInfo; edit: () => void; remove: () => void }) {
  const c = () => props.info.configuration;
  return (
    <tr>
      <td>
        <span class="mono">{c().id}</span>
        <Show when={!c().enabled}>
          {" "}
          <Badge>disabled</Badge>
        </Show>
      </td>
      <td>
        {c().frequency}, {c().format}, {c().all_versions ? "all versions" : "current objects"}
        <Show when={c().prefix}>
          <div class="subtle small">under {c().prefix}</div>
        </Show>
      </td>
      <td class="mono">
        {c().destination_bucket}
        {c().destination_prefix ? `/${c().destination_prefix}` : ""}
      </td>
      <td>
        <Show when={props.info.last} fallback={<span class="subtle">none yet</span>}>
          {(l) => (
            <span title={l().manifest}>
              {date(l().finished)}: {num(l().read)} versions, {l().files} files
            </span>
          )}
        </Show>
      </td>
      <td>
        <Show
          when={props.info.started}
          fallback={<span class="subtle">next {date(props.info.due)}</span>}
        >
          {(s) => (
            <span>
              writing since {ago(s())}: {num(props.info.seen)} versions
            </span>
          )}
        </Show>
        <Show when={props.info.failure}>
          {(f) => (
            <div class="error-text small" title={props.info.failed_at ? date(props.info.failed_at) : undefined}>
              {f()}
            </div>
          )}
        </Show>
      </td>
      <td class="num">
        <button class="small" onClick={props.edit}>
          Edit
        </button>{" "}
        <button class="small danger" onClick={props.remove}>
          Delete
        </button>
      </td>
    </tr>
  );
}

function Editor(props: { bucket: string; form: InventoryForm; fields: string[]; close: () => void; saved: () => void }) {
  const [f, setF] = createSignal<InventoryForm>(props.form);
  const set = (change: Partial<InventoryForm>) => setF((x) => ({ ...x, ...change }));
  const has = (field: string) => (f().fields ?? []).includes(field);
  const toggle = (field: string, on: boolean) => set({ fields: on ? [...(f().fields ?? []), field] : (f().fields ?? []).filter((x) => x !== field) });
  const save = async () => {
    const form = { ...f(), id: f().id.trim(), destination_account: f().destination_account?.trim() || null, encryption: f().encryption || null };
    if (await act(() => api.putInventory(props.bucket, form), `Saved ${form.id}`)) {
      props.saved();
      props.close();
    }
  };
  return (
    <Panel title={props.form.id ? `Configuration ${props.form.id}` : "New configuration"}>
      <div class="rule">
        <div class="form-row">
          <span class="label">Name</span>
          <input type="text" aria-label="ID" placeholder="daily-report" disabled={!!props.form.id} value={f().id} onInput={(e) => set({ id: e.currentTarget.value })} />
          <label class="check">
            <input type="checkbox" checked={f().enabled} onChange={(e) => set({ enabled: e.currentTarget.checked })} />
            Enabled
          </label>
        </div>
        <div class="form-row">
          <span class="label">Objects</span>
          <input type="text" placeholder="key prefix (all keys if empty)" aria-label="Key prefix" value={f().prefix ?? ""} onInput={(e) => set({ prefix: e.currentTarget.value })} />
          <select aria-label="Versions" value={f().all_versions ? "all" : "current"} onChange={(e) => set({ all_versions: e.currentTarget.value === "all" })}>
            <option value="current">Current objects</option>
            <option value="all">All versions and delete markers</option>
          </select>
          <select aria-label="Frequency" value={f().frequency} onChange={(e) => set({ frequency: e.currentTarget.value })}>
            <option value="Daily">Daily</option>
            <option value="Weekly">Weekly</option>
          </select>
        </div>
        <div class="form-row">
          <span class="label">Destination</span>
          <input type="text" placeholder="bucket" aria-label="Destination bucket" value={f().destination_bucket} onInput={(e) => set({ destination_bucket: e.currentTarget.value })} />
          <input type="text" placeholder="prefix (optional)" aria-label="Destination prefix" value={f().destination_prefix ?? ""} onInput={(e) => set({ destination_prefix: e.currentTarget.value })} />
          <select aria-label="Format" value={f().format} onChange={(e) => set({ format: e.currentTarget.value })}>
            <option value="CSV">CSV (gzipped)</option>
            <option value="Parquet">Parquet</option>
          </select>
        </div>
        <div class="form-row">
          <span class="label">Encryption</span>
          <select
            aria-label="Encryption"
            value={!f().encryption ? "" : f().encryption === "SSE-S3" ? "SSE-S3" : "kms"}
            onChange={(e) => set({ encryption: e.currentTarget.value === "kms" ? "arn:aws:kms:" : e.currentTarget.value || null })}
          >
            <option value="">The destination's default</option>
            <option value="SSE-S3">SSE-S3</option>
            <option value="kms">SSE-KMS</option>
          </select>
          <Show when={f().encryption && f().encryption !== "SSE-S3"}>
            <input type="text" placeholder="the KMS key's ARN" aria-label="KMS key" value={f().encryption ?? ""} onInput={(e) => set({ encryption: e.currentTarget.value })} />
          </Show>
        </div>
        <div class="form-row">
          <span class="label">Fields</span>
          <div>
            <For each={props.fields}>
              {(field) => (
                <label class="check small">
                  <input type="checkbox" checked={has(field)} onChange={(e) => toggle(field, e.currentTarget.checked)} />
                  {field}
                </label>
              )}
            </For>
          </div>
        </div>
        <p class="subtle small">
          Reports are written as S3 writes them, so the destination bucket's policy must allow it, with a statement such
          as:
        </p>
        <pre class="mono small">{destinationStatement(props.bucket, f())}</pre>
      </div>
      <div class="buttons">
        <button onClick={props.close}>Cancel</button>
        <button class="primary" onClick={save}>
          Save configuration
        </button>
      </div>
    </Panel>
  );
}
