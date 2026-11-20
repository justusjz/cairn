// A bucket's settings that S3 keeps as documents of their own (default
// encryption, Object Lock, Object Ownership and ACLs, server access logging,
// versioning's MFA delete), in one dialog of tabs, and what an object
// version has besides its data (its storage class, checksum, retention,
// legal hold and ACL). The server checks each as S3 does, and says why it
// refuses one.

import { For, Match, Show, Switch, createSignal, onMount } from "solid-js";
import { type AclGrant, type ObjectDetails, type StorageClassName, type VersionDetails, settingsApi } from "../api";
import { date } from "../format";
import { Badge, Loading, act, poll, toast } from "./ui";

type Tab = "encryption" | "lock" | "acl" | "logging" | "versioning";

const TABS: { id: Tab; label: string }[] = [
  { id: "encryption", label: "Default encryption" },
  { id: "lock", label: "Object Lock" },
  { id: "acl", label: "Ownership and ACL" },
  { id: "logging", label: "Access logging" },
  { id: "versioning", label: "Versioning" },
];

/** Runs `fn`, saying how it went in `setError` (cleared first) and, if it
 * went well, a toast: whether it did. */
async function run(setError: (e: string | undefined) => void, fn: () => Promise<unknown>, done: string) {
  setError(undefined);
  try {
    await fn();
  } catch (e) {
    setError(e instanceof Error ? e.message : String(e));
    return false;
  }
  toast(done);
  return true;
}

/** A bucket's settings, a tab each. */
export function BucketSettingsDialog(props: { bucket: string; onClose: () => void; changed?: () => void }) {
  let dialog!: HTMLDialogElement;
  const [tab, setTab] = createSignal<Tab>("encryption");
  onMount(() => dialog.showModal());
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <h2>
        Settings of <span class="mono">{props.bucket}</span>
      </h2>
      <div class="tabs" role="tablist">
        <For each={TABS}>
          {(t) => (
            <button
              type="button"
              role="tab"
              aria-selected={tab() === t.id}
              classList={{ active: tab() === t.id }}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          )}
        </For>
      </div>
      <Switch>
        <Match when={tab() === "encryption"}>
          <EncryptionTab bucket={props.bucket} changed={props.changed} />
        </Match>
        <Match when={tab() === "lock"}>
          <ObjectLockTab bucket={props.bucket} />
        </Match>
        <Match when={tab() === "acl"}>
          <AclTab bucket={props.bucket} />
        </Match>
        <Match when={tab() === "logging"}>
          <LoggingTab bucket={props.bucket} />
        </Match>
        <Match when={tab() === "versioning"}>
          <VersioningTab bucket={props.bucket} />
        </Match>
      </Switch>
      <div class="buttons">
        <button type="button" onClick={() => dialog.close()}>
          Close
        </button>
      </div>
    </dialog>
  );
}

/** PutBucketEncryption: what writes that ask for no encryption of their
 * own are encrypted with. */
function EncryptionTab(props: { bucket: string; changed?: () => void }) {
  const [loaded, setLoaded] = createSignal(false);
  const [had, setHad] = createSignal(false);
  const [kms, setKms] = createSignal(false);
  const [sseS3, setSseS3] = createSignal(false);
  const [algorithm, setAlgorithm] = createSignal("AES256");
  const [key, setKey] = createSignal("");
  const [bucketKey, setBucketKey] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const load = async () => {
    try {
      const e = await settingsApi.encryption(props.bucket);
      setKms(e.kms);
      setSseS3(e.sse_s3);
      setHad(!!e.configuration);
      if (e.configuration) {
        setAlgorithm(e.configuration.algorithm);
        setKey(e.configuration.kms_key_id ?? "");
        setBucketKey(!!e.configuration.bucket_key);
      }
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  onMount(load);
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = {
      algorithm: algorithm(),
      kms_key_id: algorithm() === "aws:kms" ? key().trim() : null,
      bucket_key: bucketKey(),
    };
    if (
      await run(
        setError,
        () => settingsApi.putEncryption(props.bucket, body),
        `Saved the default encryption of ${props.bucket}`,
      )
    ) {
      props.changed?.();
      load();
    }
  };
  const remove = async () => {
    if (
      !confirm(
        `Remove the default encryption of ${props.bucket}? New writes are encrypted only if they ask; what's written stays as it is.`,
      )
    )
      return;
    if (
      await run(
        setError,
        () => settingsApi.deleteEncryption(props.bucket),
        `Removed the default encryption of ${props.bucket}`,
      )
    ) {
      setHad(false);
      props.changed?.();
    }
  };
  return (
    <Show when={loaded()} fallback={<Loading error={error()} />}>
      <form onSubmit={save}>
        <p class="subtle small">
          What a write that asks for no encryption of its own (PutObject, CopyObject, CreateMultipartUpload) is
          encrypted with. What's written already stays as it is.
        </p>
        <Show when={!kms()}>
          <p class="warn-text small">The cluster has no KMS: neither can be set.</p>
        </Show>
        <p>{had() ? "The bucket has a default encryption." : <strong>The bucket has no default encryption.</strong>}</p>
        <label class="field">
          Encryption
          <select value={algorithm()} onChange={(e) => setAlgorithm(e.currentTarget.value)}>
            <option value="AES256">
              SSE-S3, under Cairn's own key{kms() && !sseS3() ? " (the cluster has none)" : ""}
            </option>
            <option value="aws:kms">SSE-KMS, under a key of the KMS</option>
          </select>
        </label>
        <Show when={algorithm() === "aws:kms"}>
          <label class="field">
            KMS key
            <input
              type="text"
              required
              placeholder="mount/key, or a key of transit"
              value={key()}
              onInput={(e) => setKey(e.currentTarget.value)}
            />
          </label>
          <p class="subtle small">Writers must be allowed to use it in the KMS, as when they name it themselves.</p>
        </Show>
        <label class="check" title="Told back to clients, as S3 does; every object has keys of its own regardless">
          <input type="checkbox" checked={bucketKey()} onChange={(e) => setBucketKey(e.currentTarget.checked)} />
          Bucket key
        </label>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <Show when={had()}>
            <button type="button" class="danger" onClick={remove}>
              Remove
            </button>
          </Show>
          <button class="primary" type="submit" disabled={!kms()}>
            Save
          </button>
        </div>
      </form>
    </Show>
  );
}

/** PutObjectLockConfiguration: a default retention, for a bucket with
 * Object Lock (or one that's versioned, which it enables for good). */
function ObjectLockTab(props: { bucket: string }) {
  const [loaded, setLoaded] = createSignal(false);
  const [enabled, setEnabled] = createSignal(false);
  const [retains, setRetains] = createSignal(false);
  const [mode, setMode] = createSignal("GOVERNANCE");
  const [count, setCount] = createSignal(30);
  const [unit, setUnit] = createSignal<"days" | "years">("days");
  const [error, setError] = createSignal<string>();
  onMount(async () => {
    try {
      const l = await settingsApi.objectLock(props.bucket);
      setEnabled(l.enabled);
      const r = l.default_retention;
      if (r) {
        setRetains(true);
        setMode(r.mode);
        setUnit(r.years != null ? "years" : "days");
        setCount(r.years ?? r.days ?? 30);
      }
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    if (
      !enabled() &&
      !confirm(`Enable Object Lock on ${props.bucket}? It can't be disabled again, and the bucket stays versioned.`)
    )
      return;
    const retention = retains()
      ? { mode: mode(), days: unit() === "days" ? count() : null, years: unit() === "years" ? count() : null }
      : null;
    if (
      await run(
        setError,
        () => settingsApi.putObjectLock(props.bucket, retention),
        `Saved the Object Lock configuration of ${props.bucket}`,
      )
    )
      setEnabled(true);
  };
  return (
    <Show when={loaded()} fallback={<Loading error={error()} />}>
      <form onSubmit={save}>
        <p class="subtle small">
          Object Lock keeps versions from being deleted while they're retained, or under a legal hold. A default
          retention is what every new version that asks for none gets, from when it's written. In GOVERNANCE mode, whom
          s3:BypassGovernanceRetention is allowed may still shorten or remove it; in COMPLIANCE mode, no one can.
        </p>
        <Show
          when={enabled()}
          fallback={
            <p>
              <strong>The bucket doesn't have Object Lock.</strong>{" "}
              <span class="subtle small">Saving enables it, for good: the bucket must be versioned.</span>
            </p>
          }
        >
          <p>
            <Badge tone="accent">enabled</Badge> <span class="subtle small">It can't be disabled again.</span>
          </p>
        </Show>
        <label class="check">
          <input type="checkbox" checked={retains()} onChange={(e) => setRetains(e.currentTarget.checked)} />
          Default retention
        </label>
        <Show when={retains()}>
          <div class="form-row">
            <select aria-label="Mode" value={mode()} onChange={(e) => setMode(e.currentTarget.value)}>
              <option value="GOVERNANCE">GOVERNANCE</option>
              <option value="COMPLIANCE">COMPLIANCE</option>
            </select>
            <span>for</span>
            <input
              type="number"
              min="1"
              aria-label="Period"
              value={count()}
              onInput={(e) => setCount(e.currentTarget.valueAsNumber)}
            />
            <select
              aria-label="Unit"
              value={unit()}
              onChange={(e) => setUnit(e.currentTarget.value as "days" | "years")}
            >
              <option value="days">days</option>
              <option value="years">years</option>
            </select>
          </div>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button class="primary" type="submit">
            {enabled() ? "Save" : "Enable Object Lock"}
          </button>
        </div>
      </form>
    </Show>
  );
}

const OWNERSHIPS: { value: string; label: string; note: string }[] = [
  {
    value: "BucketOwnerEnforced",
    label: "Bucket owner enforced",
    note: "ACLs are disabled: the bucket's account owns everything in it, and policies alone decide access.",
  },
  {
    value: "BucketOwnerPreferred",
    label: "Bucket owner preferred",
    note: "ACLs are enabled; a write that gives the bucket owner full control makes it the owner of its object.",
  },
  {
    value: "ObjectWriter",
    label: "Object writer",
    note: "ACLs are enabled; the writer's account owns what it writes.",
  },
];

const GROUPS: { value: string; label: string }[] = [
  { value: "AllUsers", label: "Everyone (unsigned requests too)" },
  { value: "AuthenticatedUsers", label: "Any signed request" },
  { value: "LogDelivery", label: "Log delivery" },
];

const PERMISSIONS = ["FULL_CONTROL", "READ", "WRITE", "READ_ACP", "WRITE_ACP"];

/** Edits an ACL's grants, row by row. */
function GrantRows(props: { grants: AclGrant[]; set: (grants: AclGrant[]) => void }) {
  const update = (i: number, change: Partial<AclGrant>) =>
    props.set(props.grants.map((g, j) => (j === i ? { ...g, ...change } : g)));
  return (
    <>
      <For each={props.grants}>
        {(g, i) => (
          <div class="form-row grant-row">
            <select
              aria-label="Grantee type"
              value={g.grantee_type}
              onChange={(e) =>
                update(i(), {
                  grantee_type: e.currentTarget.value,
                  grantee: e.currentTarget.value === "group" ? "AllUsers" : "",
                })
              }
            >
              <option value="account">Account</option>
              <option value="group">Group</option>
            </select>
            <Show
              when={g.grantee_type === "group"}
              fallback={
                <input
                  type="text"
                  placeholder="account ID"
                  aria-label="Account"
                  value={g.grantee}
                  onInput={(e) => update(i(), { grantee: e.currentTarget.value })}
                />
              }
            >
              <select
                aria-label="Group"
                value={g.grantee}
                onChange={(e) => update(i(), { grantee: e.currentTarget.value })}
              >
                <For each={GROUPS}>{(group) => <option value={group.value}>{group.label}</option>}</For>
              </select>
            </Show>
            <select
              aria-label="Permission"
              value={g.permission}
              onChange={(e) => update(i(), { permission: e.currentTarget.value })}
            >
              <For each={PERMISSIONS}>{(p) => <option value={p}>{p}</option>}</For>
            </select>
            <button type="button" class="small" onClick={() => props.set(props.grants.filter((_, j) => j !== i()))}>
              ×
            </button>
          </div>
        )}
      </For>
      <button
        type="button"
        class="small"
        onClick={() => props.set([...props.grants, { grantee_type: "account", grantee: "", permission: "READ" }])}
      >
        Add a grant
      </button>
    </>
  );
}

/** PutBucketOwnershipControls, and PutBucketAcl while ACLs are enabled. */
function AclTab(props: { bucket: string }) {
  const [loaded, setLoaded] = createSignal(false);
  const [ownership, setOwnership] = createSignal<string | null>(null);
  const [chosen, setChosen] = createSignal("BucketOwnerEnforced");
  const [enabled, setEnabled] = createSignal(false);
  const [owner, setOwner] = createSignal("");
  const [grants, setGrants] = createSignal<AclGrant[]>([]);
  const [aclError, setAclError] = createSignal<string>();
  const [error, setError] = createSignal<string>();
  const load = async () => {
    try {
      const o = await settingsApi.ownership(props.bucket);
      setOwnership(o.ownership ?? null);
      setChosen(o.ownership ?? "ObjectWriter");
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
    try {
      const a = await settingsApi.acl(props.bucket);
      setEnabled(a.enabled);
      setOwner(a.acl.owner);
      setGrants(a.acl.grants);
      setAclError(undefined);
    } catch (e) {
      setAclError((e as Error).message);
    }
  };
  onMount(load);
  const saveOwnership = async () => {
    if (
      await run(
        setError,
        () => settingsApi.putOwnership(props.bucket, chosen()),
        `Saved the Object Ownership of ${props.bucket}`,
      )
    )
      load();
  };
  const saveAcl = async () => {
    const set = grants().map((g) => ({ ...g, grantee: g.grantee.trim() }));
    if (await run(setAclError, () => settingsApi.putAcl(props.bucket, set), `Saved the ACL of ${props.bucket}`)) load();
  };
  const note = () => OWNERSHIPS.find((o) => o.value === chosen())?.note;
  return (
    <Show when={loaded()} fallback={<Loading error={error()} />}>
      <h3>Object Ownership</h3>
      <p class="subtle small">
        Whether ACLs are enabled, and who owns what's written. S3's buckets have them disabled since 2023; enable them
        only for clients that need ACLs.
        <Show when={ownership() === null}> The bucket has no ownership controls, which is as Object writer.</Show>
      </p>
      <div class="form-row">
        <select aria-label="Object Ownership" value={chosen()} onChange={(e) => setChosen(e.currentTarget.value)}>
          <For each={OWNERSHIPS}>{(o) => <option value={o.value}>{o.label}</option>}</For>
        </select>
        <button type="button" class="primary" onClick={saveOwnership}>
          Save
        </button>
      </div>
      <p class="subtle small">{note()}</p>
      <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
      <h3>Bucket ACL</h3>
      <Show when={!aclError() || owner()} fallback={<p class="error-text">{aclError()}</p>}>
        <Show
          when={enabled()}
          fallback={
            <p class="subtle small">
              ACLs are disabled: the bucket's account (<span class="mono">{owner()}</span>) has full control, and no one
              else anything.
            </p>
          }
        >
          <p class="subtle small">
            Who may do what to the bucket, besides what policies allow. The owner is <span class="mono">{owner()}</span>
            . READ lists it, WRITE writes and deletes its objects, READ_ACP and WRITE_ACP read and change this ACL.
            Accounts by their IDs.
          </p>
          <GrantRows grants={grants()} set={setGrants} />
          <Show when={aclError()}>{(e) => <p class="error-text">{e()}</p>}</Show>
          <div class="buttons">
            <button type="button" class="primary" onClick={saveAcl}>
              Save ACL
            </button>
          </div>
        </Show>
      </Show>
    </Show>
  );
}

/** PutBucketLogging: where the bucket's server access logs go. */
function LoggingTab(props: { bucket: string }) {
  const [loaded, setLoaded] = createSignal(false);
  const [had, setHad] = createSignal(false);
  const [target, setTarget] = createSignal("");
  const [prefix, setPrefix] = createSignal("");
  const [format, setFormat] = createSignal("");
  const [source, setSource] = createSignal("");
  const [error, setError] = createSignal<string>();
  const load = async () => {
    try {
      const c = (await settingsApi.logging(props.bucket)).configuration;
      setHad(!!c);
      if (c) {
        setTarget(c.target_bucket);
        setPrefix(c.target_prefix ?? "");
        setFormat(c.key_format ?? "");
        setSource(c.date_source ?? "");
      }
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  onMount(load);
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = {
      target_bucket: target().trim(),
      target_prefix: prefix(),
      key_format: format() || null,
      date_source: format() === "PartitionedPrefix" ? source() || null : null,
    };
    if (
      await run(
        setError,
        () => settingsApi.putLogging(props.bucket, body),
        `Logging the requests of ${props.bucket} to ${body.target_bucket}`,
      )
    )
      setHad(true);
  };
  const remove = async () => {
    if (!confirm(`Turn off the access logs of ${props.bucket}?`)) return;
    if (
      await run(
        setError,
        () => settingsApi.deleteLogging(props.bucket),
        `Turned off the access logs of ${props.bucket}`,
      )
    )
      setHad(false);
  };
  return (
    <Show when={loaded()} fallback={<Loading error={error()} />}>
      <form onSubmit={save}>
        <p class="subtle small">
          Server access logs: a line for each request to the bucket, written as objects into a bucket of the same
          account, every few minutes. The target's policy must let <span class="mono">logging.s3.amazonaws.com</span>{" "}
          write them (<span class="mono">s3:PutObject</span>), or they aren't delivered, as in S3.
        </p>
        <p>{had() ? "The bucket's requests are logged." : <strong>The bucket's requests aren't logged.</strong>}</p>
        <label class="field">
          Target bucket
          <input
            type="text"
            required
            placeholder="logs"
            value={target()}
            onInput={(e) => setTarget(e.currentTarget.value)}
          />
        </label>
        <label class="field">
          Prefix (optional)
          <input
            type="text"
            placeholder={`${props.bucket}/`}
            value={prefix()}
            onInput={(e) => setPrefix(e.currentTarget.value)}
          />
        </label>
        <label class="field">
          Keys
          <select value={format()} onChange={(e) => setFormat(e.currentTarget.value)}>
            <option value="">The prefix, then the time and a unique string (the default)</option>
            <option value="SimplePrefix">The same, said explicitly (SimplePrefix)</option>
            <option value="PartitionedPrefix">
              Partitioned: account, region, bucket and date first (PartitionedPrefix)
            </option>
          </select>
        </label>
        <Show when={format() === "PartitionedPrefix"}>
          <label class="field">
            Dated by
            <select value={source()} onChange={(e) => setSource(e.currentTarget.value)}>
              <option value="">The time of the events (the default)</option>
              <option value="EventTime">The time of the events (EventTime)</option>
              <option value="DeliveryTime">The time of the log's delivery (DeliveryTime)</option>
            </select>
          </label>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <Show when={had()}>
            <button type="button" class="danger" onClick={remove}>
              Turn off
            </button>
          </Show>
          <button class="primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </Show>
  );
}

/** GetBucketVersioning: its state, and MFA delete, which only the S3 API
 * changes (it needs an MFA code). */
function VersioningTab(props: { bucket: string }) {
  const versioning = poll(() => settingsApi.versioning(props.bucket));
  return (
    <Show when={versioning.data()} fallback={<Loading error={versioning.error()} />}>
      {(v) => (
        <>
          <dl class="kv">
            <dt>Versioning</dt>
            <dd>{v().status}</dd>
            <dt>MFA delete</dt>
            <dd>
              <Switch fallback={<span class="subtle">never set (disabled)</span>}>
                <Match when={v().mfa_delete === true}>
                  <Badge tone="accent">enabled</Badge>
                </Match>
                <Match when={v().mfa_delete === false}>disabled</Match>
              </Switch>
            </dd>
          </dl>
          <p class="subtle small">
            With MFA delete enabled, deleting a version or changing the bucket's versioning takes the root user's MFA
            code (<span class="mono">x-amz-mfa</span>). It's changed only through the S3 API (PutBucketVersioning), with
            one; the bucket page's switch enables and suspends versioning.
          </p>
        </>
      )}
    </Show>
  );
}

// ─── Storage classes ─────────────────────────────────────────────────────────

const [classes, setClasses] = createSignal<StorageClassName[]>();
let loadingClasses: Promise<void> | undefined;

/** The storage classes there are, loaded once. */
function storageClasses() {
  loadingClasses ??= settingsApi
    .storageClasses()
    .then((list) => {
      setClasses(list);
    })
    .catch(() => {
      loadingClasses = undefined;
    });
  return classes;
}

/** Picks a storage class (`""`: STANDARD, as a write that names none). */
export function StorageClassSelect(props: { value: string; onChange: (value: string) => void; label?: string }) {
  const list = storageClasses();
  return (
    <Show when={(list() ?? []).length > 1}>
      <select
        aria-label={props.label ?? "Storage class"}
        title="The storage class to write in"
        value={props.value}
        onChange={(e) => props.onChange(e.currentTarget.value)}
      >
        <For each={list()}>{(c) => <option value={c.name === "STANDARD" ? "" : c.name}>{c.name}</option>}</For>
      </select>
    </Show>
  );
}

// ─── Object versions ─────────────────────────────────────────────────────────

/** What each version of a key has besides its data. */
export function objectDetails(bucket: () => string, key: () => string) {
  return poll(() => settingsApi.objectDetails(bucket(), key()));
}

type VersionAction = "class" | "retention" | "acl";

/** A version's storage class, checksum, retention, legal hold and ACL, and
 * what changes them. */
export function VersionSettings(props: {
  bucket: string;
  objectKey: string;
  versionId: string;
  latest: boolean;
  details?: ObjectDetails;
  changed: () => void;
}) {
  const [editing, setEditing] = createSignal<VersionAction>();
  const version = () => props.details?.versions.find((v) => v.version_id === props.versionId);
  const toggleHold = async (v: VersionDetails) => {
    const on = !v.legal_hold;
    const msg = on
      ? `Placed a legal hold on version ${props.versionId}`
      : `Lifted the legal hold of version ${props.versionId}`;
    if (await act(() => settingsApi.putLegalHold(props.bucket, props.objectKey, props.versionId, on), msg))
      props.changed();
  };
  return (
    <Show when={props.details && version()}>
      {(v) => (
        <Show when={v().storage_class}>
          <dl class="kv">
            <dt>Storage class</dt>
            <dd>
              <span class="mono">{v().storage_class}</span>{" "}
              <Show when={props.latest}>
                <button class="small" onClick={() => setEditing("class")}>
                  Change
                </button>
              </Show>
            </dd>
            <dt>Checksum</dt>
            <dd>
              <Show when={v().checksum} fallback="none">
                {(c) => (
                  <>
                    {c().algorithm}{" "}
                    <span class="subtle">
                      ({c().kind === "COMPOSITE" ? "of its parts' checksums" : "of the whole object"})
                    </span>{" "}
                    <Show when={c().value} fallback={<span class="subtle">sealed under its encryption key</span>}>
                      <span class="mono">{c().value}</span>
                    </Show>
                  </>
                )}
              </Show>
            </dd>
            <Show when={props.details!.object_lock}>
              <dt>Retention</dt>
              <dd>
                <Show
                  when={props.details!.reads_retention}
                  fallback={<span class="subtle">your policies don't let you read it</span>}
                >
                  <Show when={v().retention} fallback="none">
                    {(r) => (
                      <>
                        <Badge tone={r().mode === "COMPLIANCE" ? "bad" : "warn"}>{r().mode}</Badge> until{" "}
                        {date(Date.parse(r().retain_until) / 1000)}
                      </>
                    )}
                  </Show>{" "}
                  <button class="small" onClick={() => setEditing("retention")}>
                    Edit
                  </button>
                </Show>
              </dd>
              <dt>Legal hold</dt>
              <dd>
                <Show
                  when={props.details!.reads_legal_hold}
                  fallback={<span class="subtle">your policies don't let you read it</span>}
                >
                  {v().legal_hold ? <Badge tone="warn">on</Badge> : "off"}{" "}
                  <button class="small" onClick={() => toggleHold(v())}>
                    {v().legal_hold ? "Lift" : "Place"}
                  </button>
                </Show>
              </dd>
            </Show>
            <Show when={props.details!.acls_enabled}>
              <dt>ACL</dt>
              <dd>
                <Show when={v().acl} fallback={<span class="subtle">your policies don't let you read it</span>}>
                  {(a) => (
                    <>
                      <span class="subtle">owner</span> <span class="mono">{a().owner}</span>
                      <span class="tag-list">
                        <For each={a().grants}>
                          {(g) => (
                            <Badge>
                              <span class="mono">
                                {g.grantee}: {g.permission}
                              </span>
                            </Badge>
                          )}
                        </For>
                      </span>{" "}
                      <button class="small" onClick={() => setEditing("acl")}>
                        Edit
                      </button>
                    </>
                  )}
                </Show>
              </dd>
            </Show>
          </dl>
          <Show when={editing() === "class"}>
            <StorageClassDialog
              bucket={props.bucket}
              objectKey={props.objectKey}
              current={v().storage_class!}
              changed={props.changed}
              onClose={() => setEditing(undefined)}
            />
          </Show>
          <Show when={editing() === "retention"}>
            <RetentionDialog
              bucket={props.bucket}
              objectKey={props.objectKey}
              versionId={props.versionId}
              retention={v().retention ?? null}
              mayBypass={props.details!.may_bypass_governance}
              changed={props.changed}
              onClose={() => setEditing(undefined)}
            />
          </Show>
          <Show when={editing() === "acl" && v().acl}>
            {(a) => (
              <ObjectAclDialog
                bucket={props.bucket}
                objectKey={props.objectKey}
                versionId={props.versionId}
                grants={a().grants}
                owner={a().owner}
                changed={props.changed}
                onClose={() => setEditing(undefined)}
              />
            )}
          </Show>
        </Show>
      )}
    </Show>
  );
}

type DialogProps = { bucket: string; objectKey: string; changed: () => void; onClose: () => void };

/** Copies the key's current version onto itself in another class, as S3
 * changes a class. */
function StorageClassDialog(props: DialogProps & { current: string }) {
  let dialog!: HTMLDialogElement;
  const list = storageClasses();
  const [chosen, setChosen] = createSignal(props.current);
  onMount(() => dialog.showModal());
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const done = `Copied ${props.objectKey} into ${chosen()}`;
    if (await act(() => settingsApi.changeStorageClass(props.bucket, props.objectKey, chosen()), done)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>Storage class</h2>
        <p class="subtle small">
          As S3 changes it: the current version is copied onto its key in the class, with its data, metadata, tags and
          encryption. In a versioned bucket that's a new version, and this one stays as it is. Into a lower class, the
          copy shares its bytes; into another, they're written again. At most 5 GiB.
        </p>
        <select aria-label="Storage class" value={chosen()} onChange={(e) => setChosen(e.currentTarget.value)}>
          <For each={list()}>{(c) => <option value={c.name}>{c.name}</option>}</For>
        </select>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={chosen() === props.current}>
            Copy into {chosen()}
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** PutObjectRetention: a version's retention, which may only be
 * lengthened, but GOVERNANCE's by whom may bypass it. */
function RetentionDialog(
  props: DialogProps & {
    versionId: string;
    retention: { mode: string; retain_until: string } | null;
    mayBypass: boolean;
  },
) {
  let dialog!: HTMLDialogElement;
  const [mode, setMode] = createSignal(props.retention?.mode ?? "GOVERNANCE");
  const [until, setUntil] = createSignal(props.retention?.retain_until.slice(0, 10) ?? "");
  const [bypass, setBypass] = createSignal(false);
  const [error, setError] = createSignal<string>();
  onMount(() => dialog.showModal());
  const put = async (body: { mode: string | null; retain_until: string | null }, done: string) => {
    const full = { ...body, bypass_governance: bypass() };
    if (
      await run(setError, () => settingsApi.putRetention(props.bucket, props.objectKey, props.versionId, full), done)
    ) {
      props.changed();
      dialog.close();
    }
  };
  const save = (e: SubmitEvent) => {
    e.preventDefault();
    put({ mode: mode(), retain_until: `${until()}T00:00:00Z` }, `Set the retention of version ${props.versionId}`);
  };
  const remove = () => {
    if (!confirm(`Remove the retention of version ${props.versionId}?`)) return;
    put({ mode: null, retain_until: null }, `Removed the retention of version ${props.versionId}`);
  };
  const governance = () => props.retention?.mode === "GOVERNANCE";
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>Retention of version {props.versionId}</h2>
        <p class="subtle small">
          Until then, the version can't be deleted. A retention may only be lengthened; one in GOVERNANCE mode may be
          shortened or removed with the bypass, if your policies allow s3:BypassGovernanceRetention. One in COMPLIANCE
          mode can't be, by anyone.
        </p>
        <div class="form-row">
          <select aria-label="Mode" value={mode()} onChange={(e) => setMode(e.currentTarget.value)}>
            <option value="GOVERNANCE">GOVERNANCE</option>
            <option value="COMPLIANCE">COMPLIANCE</option>
          </select>
          <span>until</span>
          <input
            type="date"
            required
            aria-label="Retain until"
            value={until()}
            onInput={(e) => setUntil(e.currentTarget.value)}
          />
          <span class="subtle small">(midnight UTC)</span>
        </div>
        <Show when={governance() && props.mayBypass}>
          <label class="check">
            <input type="checkbox" checked={bypass()} onChange={(e) => setBypass(e.currentTarget.checked)} />
            Bypass GOVERNANCE mode, to shorten or remove it
          </label>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <Show when={governance() && props.mayBypass}>
            <button type="button" class="danger" disabled={!bypass()} onClick={remove}>
              Remove
            </button>
          </Show>
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** PutObjectAcl, of one version. */
function ObjectAclDialog(props: DialogProps & { versionId: string; owner: string; grants: AclGrant[] }) {
  let dialog!: HTMLDialogElement;
  const [grants, setGrants] = createSignal<AclGrant[]>(props.grants.map((g) => ({ ...g })));
  const [error, setError] = createSignal<string>();
  onMount(() => dialog.showModal());
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const set = grants().map((g) => ({ ...g, grantee: g.grantee.trim() }));
    if (
      await run(
        setError,
        () => settingsApi.putObjectAcl(props.bucket, props.objectKey, props.versionId, set),
        `Saved the ACL of version ${props.versionId}`,
      )
    ) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>ACL of version {props.versionId}</h2>
        <p class="subtle small">
          Who may do what to this version, besides what policies allow. Its owner is{" "}
          <span class="mono">{props.owner}</span>. READ reads it, READ_ACP and WRITE_ACP read and change this ACL; WRITE
          means nothing on an object.
        </p>
        <GrantRows grants={grants()} set={setGrants} />
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </dialog>
  );
}
