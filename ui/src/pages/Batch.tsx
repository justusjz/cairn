// Batch Operations (see `src/batch`): jobs that do one operation to every
// object a manifest lists, as a role. Everything here is S3 Control's own
// requests (CreateJob, DescribeJob, ListJobs, UpdateJobPriority,
// UpdateJobStatus), as the signed-in identity: what its policies allow, and
// `iam:PassRole` on a new job's role.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, type JSX, Match, Show, Switch, createSignal, onMount } from "solid-js";
import { type BatchJobDetail, type BatchManifest, type BatchOperation, type Tag, api } from "../api";
import { DetailHead } from "../components/Iam";
import { Badge, Card, Loading, Panel, Table, type Tone, act, poll, toast } from "../components/ui";
import { date, duration, num, pct } from "../format";

export const batchJobHref = (id: string) => `/batch-jobs/${encodeURIComponent(id)}`;

/** An ISO 8601 time, as a date like the console's others. */
const when = (iso: string | null | undefined) => (iso ? date(Date.parse(iso) / 1000) : "–");

/** Statuses a job doesn't leave. */
const ENDED = ["Complete", "Cancelled", "Failed"];

function tone(status: string): Tone {
  if (status === "Complete") return "ok";
  if (status === "Failed" || status === "Failing") return "bad";
  if (status === "Suspended") return "warn";
  if (status === "Active" || status === "Preparing" || status === "Ready") return "accent";
  return "";
}

/** What each operation is called here. */
const OPERATIONS: [BatchOperation["type"], string, string][] = [
  ["put_tagging", "Replace tags", "S3PutObjectTagging"],
  ["delete_tagging", "Delete tags", "S3DeleteObjectTagging"],
  ["put_retention", "Object Lock retention", "S3PutObjectRetention"],
  ["put_legal_hold", "Object Lock legal hold", "S3PutObjectLegalHold"],
  ["replicate", "Replicate (Batch Replication)", "S3ReplicateObject"],
  ["copy", "Copy", "S3PutObjectCopy"],
  ["put_acl", "Set ACL", "S3PutObjectAcl"],
  ["compute_checksum", "Compute checksum", "S3ComputeObjectChecksum"],
  ["update_encryption", "Update encryption to SSE-KMS", "S3UpdateObjectEncryption"],
];

const operationName = (name: string) => OPERATIONS.find(([, , s3]) => s3 === name)?.[1] ?? name;

export default function Batch() {
  const jobs = poll(() => api.batchJobs(), 5000);
  const [creating, setCreating] = createSignal(false);
  return (
    <>
      <div class="page-head">
        <h1>Batch jobs</h1>
        <button class="primary" onClick={() => setCreating(true)}>
          New job
        </button>
      </div>
      <p class="subtle small">
        S3 Batch Operations: a job does one operation to every object of a manifest (a CSV object, an inventory report,
        or one it generates from a bucket's objects), as a role whose trust policy lets{" "}
        <span class="mono">batchoperations.s3.amazonaws.com</span> assume it. Jobs take turns at the cluster's lifecycle
        rate, highest priority first, and are kept for 90 days after they end. Tools for S3 Control work with them too (
        <span class="mono">aws s3control create-job</span>).
      </p>
      <Show when={jobs.data()} fallback={<Loading error={jobs.error()} />}>
        {(list) => (
          <Panel>
            <Table
              count={list().length}
              empty="No jobs yet."
              columns={[
                "Job",
                "Operation",
                "Status",
                { label: "Progress", num: true },
                { label: "Priority", num: true },
                "Created",
              ]}
            >
              <For each={list()}>
                {(j) => (
                  <tr>
                    <td>
                      <A class="mono" href={batchJobHref(j.id)}>
                        {j.id.slice(0, 8)}
                      </A>
                      <Show when={j.description}>{(d) => <div class="subtle small">{d()}</div>}</Show>
                    </td>
                    <td>{operationName(j.operation)}</td>
                    <td>
                      <Badge tone={tone(j.status)}>{j.status}</Badge>
                    </td>
                    <td class="num">
                      {num(j.succeeded + j.failed)} / {num(j.total)}
                      <Show when={j.failed}>
                        {" "}
                        <Badge tone="bad">{num(j.failed)} failed</Badge>
                      </Show>
                    </td>
                    <td class="num">{j.priority}</td>
                    <td>{when(j.created_at)}</td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={creating()}>
        <NewJobDialog onClose={() => setCreating(false)} changed={jobs.refresh} />
      </Show>
    </>
  );
}

/** The new job's form, as typed. */
type Form = {
  operation: BatchOperation["type"];
  tags: string;
  mode: string;
  retainUntil: string;
  bypass: boolean;
  hold: boolean;
  target: string;
  targetPrefix: string;
  storageClass: string;
  acl: string;
  algorithm: string;
  checksumType: string;
  kmsKey: string;
  manifest: BatchManifest["type"];
  bucket: string;
  key: string;
  etag: string;
  versionIds: boolean;
  prefix: string;
  suffix: string;
  createdAfter: string;
  createdBefore: string;
  eligible: boolean;
  replicationStatus: string;
  outputBucket: string;
  outputPrefix: string;
  role: string;
  priority: number;
  description: string;
  confirm: boolean;
  report: boolean;
  reportBucket: string;
  reportPrefix: string;
  failedOnly: boolean;
};

const BLANK: Form = {
  operation: "put_tagging",
  tags: "",
  mode: "GOVERNANCE",
  retainUntil: "",
  bypass: false,
  hold: true,
  target: "",
  targetPrefix: "",
  storageClass: "",
  acl: "private",
  algorithm: "CRC64NVME",
  checksumType: "FULL_OBJECT",
  kmsKey: "",
  manifest: "generate",
  bucket: "",
  key: "",
  etag: "",
  versionIds: false,
  prefix: "",
  suffix: "",
  createdAfter: "",
  createdBefore: "",
  eligible: false,
  replicationStatus: "",
  outputBucket: "",
  outputPrefix: "",
  role: "",
  priority: 10,
  description: "",
  confirm: true,
  report: true,
  reportBucket: "",
  reportPrefix: "",
  failedOnly: true,
};

/** `key=value` lines (or `key=value, …`), as tags. */
function parseTags(text: string): Tag[] {
  return text
    .split(/[\n,]/)
    .map((t) => t.trim())
    .filter(Boolean)
    .map((t) => {
      const i = t.indexOf("=");
      return i < 0 ? { key: t, value: "" } : { key: t.slice(0, i).trim(), value: t.slice(i + 1).trim() };
    });
}

/** A `datetime-local` (or date) input's value, as ISO 8601 (empty if none). */
const iso = (local: string) => (local ? new Date(local).toISOString() : "");

function operationOf(f: Form): BatchOperation {
  switch (f.operation) {
    case "put_tagging":
      return { type: "put_tagging", tags: parseTags(f.tags) };
    case "put_retention":
      return {
        type: "put_retention",
        mode: f.mode,
        retain_until: f.mode ? iso(f.retainUntil) : "",
        bypass_governance: f.bypass,
      };
    case "put_legal_hold":
      return { type: "put_legal_hold", on: f.hold };
    case "copy":
      return {
        type: "copy",
        target_bucket: f.target.trim(),
        target_prefix: f.targetPrefix,
        storage_class: f.storageClass,
        canned_acl: "",
      };
    case "put_acl":
      return { type: "put_acl", canned_acl: f.acl };
    case "compute_checksum":
      return { type: "compute_checksum", algorithm: f.algorithm, checksum_type: f.checksumType };
    case "update_encryption":
      return { type: "update_encryption", kms_key_arn: f.kmsKey.trim(), bucket_key_enabled: false };
    default:
      return { type: f.operation } as BatchOperation;
  }
}

/** The manifest object's ETag: as typed, or its current version's. */
async function etagOf(f: Form): Promise<string> {
  if (f.etag.trim()) return f.etag.trim();
  const info = await api.object(f.bucket.trim(), f.key.trim());
  const current = info.versions.find((v) => v.latest && !v.delete_marker);
  if (!current?.etag) throw new Error(`There's no object ${f.key} in ${f.bucket} (or you may not see it).`);
  return current.etag;
}

async function manifestOf(f: Form): Promise<BatchManifest> {
  switch (f.manifest) {
    case "csv":
      return {
        type: "csv",
        bucket: f.bucket.trim(),
        key: f.key.trim(),
        etag: await etagOf(f),
        version_ids: f.versionIds,
        version_id: "",
      };
    case "inventory":
      return { type: "inventory", bucket: f.bucket.trim(), key: f.key.trim(), etag: await etagOf(f), version_id: "" };
    default:
      return {
        type: "generate",
        source_bucket: f.bucket.trim(),
        prefixes: f.prefix ? [f.prefix] : [],
        suffixes: f.suffix ? [f.suffix] : [],
        created_after: iso(f.createdAfter),
        created_before: iso(f.createdBefore),
        storage_classes: [],
        eligible_for_replication: f.operation === "replicate" && f.eligible,
        replication_statuses: f.operation === "replicate" && f.replicationStatus ? [f.replicationStatus] : [],
        output_bucket: f.outputBucket.trim(),
        output_prefix: f.outputPrefix.trim(),
      };
  }
}

function Row(props: { label: string; children: JSX.Element }) {
  return (
    <div class="form-row">
      <span class="label">{props.label}</span>
      {props.children}
    </div>
  );
}

function NewJobDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const navigate = useNavigate();
  const [f, setF] = createSignal<Form>(BLANK);
  const set = (change: Partial<Form>) => setF((x) => ({ ...x, ...change }));
  const [error, setError] = createSignal<string>();
  const [busy, setBusy] = createSignal(false);
  const text = (field: keyof Form, placeholder: string, label: string) => (
    <input
      type="text"
      placeholder={placeholder}
      aria-label={label}
      value={f()[field] as string}
      onInput={(e) => set({ [field]: e.currentTarget.value } as Partial<Form>)}
    />
  );
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const form = f();
      const made = await api.createBatchJob({
        description: form.description.trim(),
        priority: form.priority,
        confirmation_required: form.confirm,
        role_arn: form.role.trim(),
        operation: operationOf(form),
        manifest: await manifestOf(form),
        report: {
          enabled: form.report,
          bucket: form.reportBucket.trim(),
          prefix: form.reportPrefix.trim(),
          failed_only: form.failedOnly,
        },
      });
      toast(form.confirm ? "Created the job: confirm it once it's prepared" : "Created the job");
      props.changed();
      dialog.close();
      navigate(batchJobHref(made.id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={create}>
        <h2>New batch job</h2>
        <h3>Operation</h3>
        <Row label="Operation">
          <select
            aria-label="Operation"
            value={f().operation}
            onChange={(e) => set({ operation: e.currentTarget.value as Form["operation"] })}
          >
            <For each={OPERATIONS}>{([value, label]) => <option value={value}>{label}</option>}</For>
          </select>
        </Row>
        <Switch>
          <Match when={f().operation === "put_tagging"}>
            <Row label="Tags">
              <textarea
                class="mono"
                rows={3}
                aria-label="Tags"
                placeholder={"key=value, one a line (none removes them)"}
                value={f().tags}
                onInput={(e) => set({ tags: e.currentTarget.value })}
              />
            </Row>
          </Match>
          <Match when={f().operation === "put_retention"}>
            <Row label="Retention">
              <select aria-label="Mode" value={f().mode} onChange={(e) => set({ mode: e.currentTarget.value })}>
                <option value="GOVERNANCE">GOVERNANCE</option>
                <option value="COMPLIANCE">COMPLIANCE</option>
                <option value="">None (removes it)</option>
              </select>
              <Show when={f().mode}>
                <input
                  type="datetime-local"
                  aria-label="Retain until"
                  required
                  value={f().retainUntil}
                  onInput={(e) => set({ retainUntil: e.currentTarget.value })}
                />
              </Show>
              <label class="check">
                <input
                  type="checkbox"
                  checked={f().bypass}
                  onChange={(e) => set({ bypass: e.currentTarget.checked })}
                />
                Bypass GOVERNANCE
              </label>
            </Row>
          </Match>
          <Match when={f().operation === "put_legal_hold"}>
            <Row label="Legal hold">
              <select
                aria-label="Legal hold"
                value={f().hold ? "ON" : "OFF"}
                onChange={(e) => set({ hold: e.currentTarget.value === "ON" })}
              >
                <option value="ON">On</option>
                <option value="OFF">Off (lifts it)</option>
              </select>
            </Row>
          </Match>
          <Match when={f().operation === "copy"}>
            <Row label="Copy to">
              {text("target", "bucket", "Target bucket")}
              {text("targetPrefix", "key prefix (optional)", "Target key prefix")}
              {text("storageClass", "storage class (STANDARD if empty)", "Storage class")}
            </Row>
          </Match>
          <Match when={f().operation === "put_acl"}>
            <Row label="Canned ACL">
              <select aria-label="Canned ACL" value={f().acl} onChange={(e) => set({ acl: e.currentTarget.value })}>
                <For
                  each={[
                    "private",
                    "public-read",
                    "public-read-write",
                    "aws-exec-read",
                    "authenticated-read",
                    "bucket-owner-read",
                    "bucket-owner-full-control",
                  ]}
                >
                  {(acl) => <option value={acl}>{acl}</option>}
                </For>
              </select>
            </Row>
          </Match>
          <Match when={f().operation === "compute_checksum"}>
            <Row label="Checksum">
              <select
                aria-label="Algorithm"
                value={f().algorithm}
                onChange={(e) => set({ algorithm: e.currentTarget.value })}
              >
                <For each={["CRC64NVME", "CRC32", "CRC32C", "SHA1", "SHA256", "MD5"]}>
                  {(a) => <option value={a}>{a}</option>}
                </For>
              </select>
              <select
                aria-label="Checksum type"
                value={f().checksumType}
                onChange={(e) => set({ checksumType: e.currentTarget.value })}
              >
                <option value="FULL_OBJECT">FULL_OBJECT</option>
                <option value="COMPOSITE">COMPOSITE</option>
              </select>
            </Row>
          </Match>
          <Match when={f().operation === "update_encryption"}>
            <Row label="KMS key">{text("kmsKey", "arn:aws:kms:…:key/…", "KMS key ARN")}</Row>
          </Match>
        </Switch>
        <h3>Objects</h3>
        <Row label="Manifest">
          <select
            aria-label="Manifest"
            value={f().manifest}
            onChange={(e) => set({ manifest: e.currentTarget.value as Form["manifest"] })}
          >
            <option value="generate">Generated from a bucket's objects</option>
            <option value="csv">A CSV object</option>
            <option value="inventory">An inventory report's manifest.json</option>
          </select>
        </Row>
        <Show
          when={f().manifest === "generate"}
          fallback={
            <>
              <Row label="Object">
                {text("bucket", "bucket", "Manifest bucket")}
                {text("key", f().manifest === "csv" ? "key of the CSV object" : "…/manifest.json", "Manifest key")}
              </Row>
              <Row label="ETag">
                {text("etag", "its current version's, if empty", "Manifest ETag")}
                <Show when={f().manifest === "csv"}>
                  <label class="check">
                    <input
                      type="checkbox"
                      checked={f().versionIds}
                      onChange={(e) => set({ versionIds: e.currentTarget.checked })}
                    />
                    Lines have version IDs
                  </label>
                </Show>
              </Row>
              <p class="subtle small">
                <Show
                  when={f().manifest === "csv"}
                  fallback="Its data files are read as the report says (CSV or Parquet)."
                >
                  Lines of <span class="mono">bucket,key</span> (or <span class="mono">bucket,key,versionId</span>),
                  keys URL-encoded.
                </Show>{" "}
                The job reads it as its role, pinned to its ETag.
              </p>
            </>
          }
        >
          <Row label="Source">
            {text("bucket", "bucket", "Source bucket")}
            {text("prefix", "key prefix (optional)", "Key prefix")}
            {text("suffix", "key suffix (optional)", "Key suffix")}
          </Row>
          <Row label="Created">
            <input
              type="date"
              aria-label="Created after"
              value={f().createdAfter}
              onInput={(e) => set({ createdAfter: e.currentTarget.value })}
            />
            <span class="subtle">to</span>
            <input
              type="date"
              aria-label="Created before"
              value={f().createdBefore}
              onInput={(e) => set({ createdBefore: e.currentTarget.value })}
            />
          </Row>
          <Show when={f().operation === "replicate"}>
            <Row label="Replication">
              <select
                aria-label="Replication status"
                value={f().replicationStatus}
                onChange={(e) => set({ replicationStatus: e.currentTarget.value })}
              >
                <option value="">Any replication status</option>
                <option value="NONE">Never replicated (NONE)</option>
                <option value="FAILED">FAILED</option>
                <option value="COMPLETED">COMPLETED</option>
                <option value="REPLICA">REPLICA</option>
              </select>
              <label class="check">
                <input
                  type="checkbox"
                  checked={f().eligible}
                  onChange={(e) => set({ eligible: e.currentTarget.checked })}
                />
                Only what the bucket's rules replicate
              </label>
            </Row>
          </Show>
          <Row label="Write it to">
            {text("outputBucket", "bucket (optional: kept internally if empty)", "Manifest output bucket")}
            {text("outputPrefix", "prefix (optional)", "Manifest output prefix")}
          </Row>
          <p class="subtle small">
            In a versioned bucket, every version that isn't a delete marker; else every current object. The role must be
            allowed <span class="mono">s3:PutInventoryConfiguration</span> on the source bucket.
          </p>
        </Show>
        <h3>Job</h3>
        <Row label="Role">{text("role", "arn:aws:iam::…:role/batch", "Role ARN")}</Row>
        <Row label="Priority">
          <input
            type="number"
            min="0"
            aria-label="Priority"
            value={f().priority}
            onInput={(e) => set({ priority: e.currentTarget.valueAsNumber || 0 })}
          />
          {text("description", "description (optional)", "Description")}
        </Row>
        <Row label="">
          <label class="check">
            <input type="checkbox" checked={f().confirm} onChange={(e) => set({ confirm: e.currentTarget.checked })} />
            Wait for confirmation once it's prepared (its count of tasks known)
          </label>
        </Row>
        <h3>Completion report</h3>
        <Row label="Report">
          <label class="check">
            <input type="checkbox" checked={f().report} onChange={(e) => set({ report: e.currentTarget.checked })} />
            Write one
          </label>
          <Show when={f().report}>
            {text("reportBucket", "bucket", "Report bucket")}
            {text("reportPrefix", "prefix (optional)", "Report prefix")}
            <label class="check">
              <input
                type="checkbox"
                checked={f().failedOnly}
                onChange={(e) => set({ failedOnly: e.currentTarget.checked })}
              />
              Failed tasks only
            </label>
          </Show>
        </Row>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={busy()}>
            Create job
          </button>
        </div>
      </form>
    </dialog>
  );
}

export function BatchJobPage() {
  const params = useParams();
  const id = () => params.id ?? "";
  const job = poll(() => api.batchJob(id()), 5000);
  return (
    <>
      <DetailHead kind="Batch jobs" href="/batch-jobs" name={id()}>
        <Show when={job.data()}>{(j) => <Actions job={j()} changed={job.refresh} />}</Show>
      </DetailHead>
      <Show when={job.data()} fallback={<Loading error={job.error()} />}>
        {(j) => <JobView job={j()} changed={job.refresh} />}
      </Show>
    </>
  );
}

function Actions(props: { job: BatchJobDetail; changed: () => void }) {
  const awaiting = () => props.job.suspended_cause === "AWAITING_CONFIRMATION";
  const confirmJob = async () => {
    if (!confirm(`Run this job on ${num(props.job.total)} objects?`)) return;
    if (await act(() => api.setBatchJobStatus(props.job.id, "Ready"), "Confirmed the job")) props.changed();
  };
  const cancel = async () => {
    const reason = prompt("Cancel the job? Tasks done stay done. Why (optional):");
    if (reason === null) return;
    if (await act(() => api.setBatchJobStatus(props.job.id, "Cancelled", reason.trim()), "Cancelled the job"))
      props.changed();
  };
  return (
    <>
      <Show when={awaiting()}>
        <button class="primary" onClick={confirmJob}>
          Confirm job
        </button>
      </Show>
      <Show when={!ENDED.includes(props.job.status) && props.job.status !== "Cancelling"}>
        <button class="danger" onClick={cancel}>
          Cancel job
        </button>
      </Show>
    </>
  );
}

/** Settings, as a list of names and values. */
function Settings(props: { settings: { name: string; value: string }[] }) {
  return (
    <dl class="kv">
      <For each={props.settings}>
        {(s) => (
          <>
            <dt>{s.name}</dt>
            <dd class="mono">{s.value || "–"}</dd>
          </>
        )}
      </For>
    </dl>
  );
}

function JobView(props: { job: BatchJobDetail; changed: () => void }) {
  const j = () => props.job;
  const done = () => j().succeeded + j().failed;
  const [priority, setPriority] = createSignal(j().priority);
  const savePriority = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.setBatchJobPriority(j().id, priority()), "Changed the priority")) props.changed();
  };
  return (
    <>
      <p class="subtle small mono">{j().arn}</p>
      <Show when={j().suspended_cause === "AWAITING_CONFIRMATION"}>
        <Panel>
          <p>
            <Badge tone="warn">Awaiting confirmation</Badge> The job is prepared: it has {num(j().total)} tasks. Confirm
            it to run them, or cancel it.
          </p>
        </Panel>
      </Show>
      <div class="cards">
        <Card label="Status" value={j().status} tone={tone(j().status)} note={j().status_reason ?? undefined} />
        <Card
          label="Done"
          value={`${num(done())} / ${num(j().total)}`}
          note={j().total ? pct(done(), j().total) : "Counted while it's prepared"}
        />
        <Card label="Succeeded" value={num(j().succeeded)} tone={j().succeeded ? "ok" : ""} />
        <Card
          label="Failed"
          value={num(j().failed)}
          tone={j().failed ? "bad" : ""}
          note={`${duration(j().active_seconds)} active`}
        />
      </div>
      <div class="grid cols-2">
        <Panel title="Operation" note={j().operation}>
          <Show
            when={j().operation_settings.length}
            fallback={<p class="subtle">{operationName(j().operation)}, nothing to set.</p>}
          >
            <Settings settings={j().operation_settings} />
          </Show>
        </Panel>
        <Panel title="Objects">
          <Show when={j().manifest}>
            {(m) => (
              <dl class="kv">
                <dt>Manifest</dt>
                <dd class="mono">{m().object_arn}</dd>
                <dt>Format</dt>
                <dd class="mono">{m().format}</dd>
                <Show when={m().fields.length}>
                  <dt>Fields</dt>
                  <dd class="mono">{m().fields.join(", ")}</dd>
                </Show>
                <dt>ETag</dt>
                <dd class="mono">{m().etag}</dd>
                <Show when={m().version_id}>
                  <dt>Version</dt>
                  <dd class="mono">{m().version_id}</dd>
                </Show>
              </dl>
            )}
          </Show>
          <Show when={j().generator}>
            {(g) => (
              <>
                <p class="subtle small">Generated from a bucket's objects:</p>
                <Settings settings={g()} />
                <Show when={j().generated_manifest}>
                  {(m) => (
                    <p class="subtle small">
                      Written to <span class="mono">{m().object_arn}</span>
                    </p>
                  )}
                </Show>
              </>
            )}
          </Show>
        </Panel>
        <Panel title="Job">
          <dl class="kv">
            <Show when={j().description}>
              <dt>Description</dt>
              <dd>{j().description}</dd>
            </Show>
            <dt>Role</dt>
            <dd class="mono">{j().role_arn}</dd>
            <dt>Created</dt>
            <dd>{when(j().created_at)}</dd>
            <Show when={j().terminated_at}>
              <dt>Ended</dt>
              <dd>{when(j().terminated_at)}</dd>
            </Show>
            <Show when={j().suspended_at}>
              <dt>Suspended</dt>
              <dd>
                {when(j().suspended_at)} <span class="mono small">{j().suspended_cause}</span>
              </dd>
            </Show>
          </dl>
          <form class="form-row" onSubmit={savePriority}>
            <span class="label">Priority</span>
            <input
              type="number"
              min="0"
              aria-label="Priority"
              value={priority()}
              onInput={(e) => setPriority(e.currentTarget.valueAsNumber || 0)}
            />
            <button type="submit" disabled={priority() === j().priority}>
              Change priority
            </button>
          </form>
        </Panel>
        <Panel title="Completion report">
          <Show when={j().report.enabled} fallback={<p class="subtle">None.</p>}>
            <dl class="kv">
              <dt>Bucket</dt>
              <dd class="mono">{j().report.bucket}</dd>
              <Show when={j().report.prefix}>
                <dt>Prefix</dt>
                <dd class="mono">{j().report.prefix}</dd>
              </Show>
              <dt>Tasks</dt>
              <dd>{j().report.scope === "FailedTasksOnly" ? "Failed only" : "All"}</dd>
            </dl>
            <p class="subtle small">
              Written under <span class="mono">job-{j().id}/</span> there, once the job ends.
            </p>
          </Show>
        </Panel>
      </div>
      <Show when={j().failures.length}>
        <Panel title="Failures" note="Why the job failed.">
          <Table count={j().failures.length} columns={["Code", "Reason"]}>
            <For each={j().failures}>
              {(f) => (
                <tr>
                  <td class="mono">{f.code}</td>
                  <td>{f.reason}</td>
                </tr>
              )}
            </For>
          </Table>
        </Panel>
      </Show>
    </>
  );
}
