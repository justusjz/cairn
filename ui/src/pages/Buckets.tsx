import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { For, Match, Show, Switch, createEffect, createSignal, on, onMount } from "solid-js";
import { type Bucket, type BucketAccess, type Entry, type PublicAccessBlock, api, downloadUrl } from "../api";
import { CorsDialog, TagsDialog } from "../components/Editors";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { bytes, date, num, pretty } from "../format";

const enc = encodeURIComponent;

/** Tags of a bucket or an object version (PutBucketTagging,
 * PutObjectTagging), as `key=value` badges; shown, not edited. */
function TagList(props: { tags: { key: string; value: string }[] }) {
  return (
    <Show when={props.tags.length} fallback={<span class="subtle">none</span>}>
      <span class="tag-list">
        <For each={props.tags}>
          {(t) => (
            <Badge>
              <span class="mono">
                {t.key}={t.value}
              </span>
            </Badge>
          )}
        </For>
      </span>
    </Show>
  );
}

export function bucketUrl(bucket: string, prefix = "", deleted = false) {
  const query = new URLSearchParams();
  if (prefix) query.set("prefix", prefix);
  if (deleted) query.set("deleted", "1");
  const q = query.toString();
  return `/buckets/${enc(bucket)}` + (q ? "?" + q : "");
}

function objectUrl(bucket: string, key: string) {
  return `/buckets/${enc(bucket)}/object?key=${enc(key)}`;
}

/** Whether a bucket is open to anyone, as its policy, its public access
 * block and the cluster's say. */
function PublicAccess(props: { bucket: Bucket; cluster: PublicAccessBlock }) {
  const restricted = () => !!props.bucket.public_access_block?.restrict_public_buckets || props.cluster.restrict_public_buckets;
  const blocked = () => !!props.bucket.public_access_block?.block_public_policy || props.cluster.block_public_policy;
  return (
    <Switch fallback={<span class="subtle">not blocked</span>}>
      <Match when={props.bucket.public && !restricted()}>
        <span title="Its policy lets anyone, unsigned requests too, do what it allows">
          <Badge tone="bad">public</Badge>
        </span>
      </Match>
      <Match when={props.bucket.public}>
        <span title="Its policy is public, but RestrictPublicBuckets lets it allow unsigned requests nothing">
          <Badge tone="warn">public policy, restricted</Badge>
        </span>
      </Match>
      <Match when={blocked() && restricted()}>
        <Badge tone="ok">blocked</Badge>
      </Match>
      <Match when={blocked() || restricted()}>
        <Badge>partly blocked</Badge>
      </Match>
    </Switch>
  );
}

/** The cluster's public access block, which every bucket gets too: the
 * operator's to set (on the Accounts page). */
export function ClusterBlock(props: { block: PublicAccessBlock; changed: () => void }) {
  const set = async (name: string, on: boolean) => {
    if (await act(() => api.setSetting(name, on ? 1 : 0), `${name} ${on ? "on" : "off"}`)) props.changed();
  };
  return (
    <div class="toolbar">
      <span class="subtle">For every bucket:</span>
      <label class="check" title="Refuse bucket policies that make a bucket public, whatever its own block says">
        <input
          type="checkbox"
          checked={props.block.block_public_policy}
          onChange={(e) => set("block-public-policy", e.currentTarget.checked)}
        />
        Block public policies
      </label>
      <label class="check" title="Let no public bucket policy allow unsigned requests anything">
        <input
          type="checkbox"
          checked={props.block.restrict_public_buckets}
          onChange={(e) => set("restrict-public-buckets", e.currentTarget.checked)}
        />
        Restrict public buckets
      </label>
    </div>
  );
}

export function BucketList() {
  const data = poll(() => Promise.all([api.buckets(), api.publicAccess()]));
  const buckets = { data: () => data.data()?.[0], error: data.error, refresh: data.refresh };
  const cluster = () => data.data()?.[1];
  const [name, setName] = createSignal("");
  const [objectLock, setObjectLock] = createSignal(false);
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    if (
      objectLock() &&
      !confirm(`Create "${n}" with Object Lock? It can't be disabled again, and the bucket stays versioned.`)
    )
      return;
    if (await act(() => api.createBucket(n, objectLock()), `Created bucket ${n}`)) {
      setName("");
      setObjectLock(false);
      buckets.refresh();
    }
  };
  const remove = async (n: string) => {
    if (!confirm(`Delete bucket "${n}"? It must be empty.`)) return;
    if (await act(() => api.deleteBucket(n), `Deleted bucket ${n}`)) buckets.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Buckets</h1>
        <form class="form-row" onSubmit={create}>
          <input type="text" placeholder="new-bucket-name" aria-label="Bucket name" value={name()} onInput={(e) => setName(e.currentTarget.value)} />
          <label title="Keeps versions from being deleted for a retention period, or under a legal hold, as S3's Object Lock">
            <input type="checkbox" checked={objectLock()} onChange={(e) => setObjectLock(e.currentTarget.checked)} />
            Object Lock
          </label>
          <button class="primary" type="submit">
            Create bucket
          </button>
        </form>
      </div>
      <Show when={buckets.data()} fallback={<Loading error={buckets.error()} />}>
        {(list) => (
          <Panel>
            <Table
              count={list().length}
              empty="No buckets yet."
              columns={[
                "Name",
                "Versioning",
                "Default encryption",
                "Public access",
                { label: "Objects", num: true },
                { label: "Size", num: true },
                { label: "Older versions", num: true },
                { label: "Uploads", num: true },
                { label: "Users with access", num: true },
                "Tags",
                "Created",
                "",
              ]}
            >
              <For each={list()}>
                {(b) => (
                  <tr>
                    <td class="key">
                      <A href={bucketUrl(b.name)}>{b.name}</A>
                    </td>
                    <td>
                      {b.object_lock ? (
                        <Badge tone="accent">versioned, locked</Badge>
                      ) : b.versioning === "enabled" ? (
                        <Badge tone="accent">versioned</Badge>
                      ) : b.versioning === "suspended" ? (
                        <Badge tone="warn">suspended</Badge>
                      ) : (
                        <Badge>unversioned</Badge>
                      )}
                    </td>
                    <td>
                      <Show when={b.default_kms_key} fallback={<span class="subtle">none</span>}>
                        {(key) => (
                          <span title="Writes that ask for no encryption of their own get SSE-KMS under this key">
                            SSE-KMS <span class="mono">{key()}</span>
                          </span>
                        )}
                      </Show>
                    </td>
                    <td>
                      <PublicAccess bucket={b} cluster={cluster()!} />
                    </td>
                    <td class="num">{num(b.objects)}</td>
                    <td class="num">{bytes(b.bytes)}</td>
                    <td class="num">{b.versions > b.objects ? `${num(b.versions - b.objects)} · ${bytes(b.version_bytes - b.bytes)}` : "–"}</td>
                    <td class="num">{num(b.uploads)}</td>
                    <td class="num">{num(b.roles)}</td>
                    <td>
                      <TagList tags={b.tags} />
                    </td>
                    <td>{date(b.created_at)}</td>
                    <td class="actions">
                      <button class="small danger" onClick={() => remove(b.name)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
    </>
  );
}

/** Buckets / bucket / each directory of `prefix`. */
function Crumbs(props: { bucket: string; prefix: string; deleted?: boolean }) {
  const dirs = () => {
    let acc = "";
    return props.prefix
      .split("/")
      .slice(0, -1)
      .map((seg) => {
        acc += seg + "/";
        return { seg, prefix: acc };
      });
  };
  return (
    <div class="crumbs">
      <A href="/buckets">Buckets</A>
      <span class="sep">/</span>
      <A href={bucketUrl(props.bucket, "", props.deleted)}>{props.bucket}</A>
      <For each={dirs()}>
        {(d) => (
          <>
            <span class="sep">/</span>
            <A href={bucketUrl(props.bucket, d.prefix, props.deleted)}>{d.seg || "(empty)"}</A>
          </>
        )}
      </For>
    </div>
  );
}

export function BucketBrowser() {
  const params = useParams();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const bucket = () => params.bucket ?? "";
  const prefix = () => (typeof search.prefix === "string" ? search.prefix : "");
  const deleted = () => search.deleted === "1";
  const [entries, setEntries] = createSignal<Entry[]>([]);
  const [next, setNext] = createSignal<string | null>(null);
  const [loaded, setLoaded] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [goto, setGoto] = createSignal("");
  const [access, setAccess] = createSignal(false);
  const [uploading, setUploading] = createSignal<string>();
  // The bucket's versioning state, for its switch.
  const [versioning, setVersioning] = createSignal<string>();
  const [bucketTags, setBucketTags] = createSignal<{ key: string; value: string }[]>([]);
  const [editing, setEditing] = createSignal<"tags" | "cors">();
  const loadVersioning = async () => {
    try {
      const b = (await api.buckets()).find((b) => b.name === bucket());
      setVersioning(b?.versioning);
      setBucketTags(b?.tags ?? []);
    } catch {
      setVersioning(undefined);
    }
  };
  createEffect(on(bucket, loadVersioning));
  const toggleVersioning = async () => {
    const on = versioning() !== "enabled";
    if (!on && !confirm("Suspend versioning? Existing versions stay; new writes replace the null version.")) return;
    const msg = on ? "Versioning enabled" : "Versioning suspended";
    if (await act(() => api.setVersioning(bucket(), on ? "Enabled" : "Suspended"), msg)) loadVersioning();
  };
  /** Uploads the chosen files under the current prefix, one by one. */
  const upload = async (files: FileList | null) => {
    if (!files) return;
    for (const file of Array.from(files)) {
      const key = prefix() + file.name;
      setUploading(`Uploading ${file.name} (${bytes(file.size)})…`);
      const progress = (sent: number) =>
        setUploading(`Uploading ${file.name}: ${bytes(sent)} of ${bytes(file.size)} (${Math.floor((sent / file.size) * 100)}%)`);
      if (!(await act(() => api.upload(bucket(), key, file, progress), `Uploaded ${key}`))) break;
    }
    setUploading(undefined);
    restart();
  };
  const remove = async (key: string) => {
    if (!confirm(`Delete "${key}"? In a versioned bucket, its versions stay, under a delete marker.`)) return;
    if (await act(() => api.deleteObject(bucket(), key), `Deleted ${key}`)) restart();
  };

  // Counts the listings started, so that a page of an old one is dropped.
  let listing = 0;
  const load = async (after: string) => {
    const current = listing;
    try {
      const page = await api.objects(bucket(), prefix(), after, deleted());
      if (current !== listing) return;
      setEntries((e) => [...e, ...page.entries]);
      setNext(page.next ?? null);
      setLoaded(true);
    } catch (e) {
      if (current === listing) setError((e as Error).message);
    }
  };
  const restart = () => {
    listing++;
    setEntries([]);
    setNext(null);
    setLoaded(false);
    setError(undefined);
    load("");
  };
  // Start over whenever the listing's bucket, prefix or filter changes.
  createEffect(on([bucket, prefix, deleted], restart));

  return (
    <>
      <h1>
        Bucket <span class="mono">{bucket()}</span>
      </h1>
      <Crumbs bucket={bucket()} prefix={prefix()} deleted={deleted()} />
      <div class="toolbar">
        <label class="check">
          <input type="checkbox" checked={deleted()} onChange={(e) => navigate(bucketUrl(bucket(), prefix(), e.currentTarget.checked))} />
          Show deleted keys
        </label>
        <A class="button" href={`/buckets/${enc(bucket())}/lifecycle`}>
          Lifecycle rules
        </A>
        <button onClick={() => setAccess(true)}>Access and policy</button>
        <button onClick={() => setEditing("tags")}>Tags{bucketTags().length ? ` (${bucketTags().length})` : ""}</button>
        <button onClick={() => setEditing("cors")}>CORS</button>
        <Show when={versioning()}>
          {(v) => (
            <button onClick={toggleVersioning} title={`Versioning is ${v()}`}>
              {v() === "enabled" ? "Suspend versioning" : "Enable versioning"}
            </button>
          )}
        </Show>
        <label class="button primary file-button">
          Upload files
          <input type="file" multiple onChange={(e) => upload(e.currentTarget.files).then(() => (e.currentTarget.value = ""))} />
        </label>
        <Show when={uploading()}>{(u) => <span class="subtle">{u()}</span>}</Show>
        <span class="spacer" />
        <form
          class="form-row"
          onSubmit={(e) => {
            e.preventDefault();
            if (goto()) navigate(objectUrl(bucket(), goto()));
          }}
        >
          <input type="search" placeholder="Go to key…" aria-label="Key" value={goto()} onInput={(e) => setGoto(e.currentTarget.value)} />
          <button type="submit">Open</button>
        </form>
      </div>
      <Show when={access()}>
        <AccessDialog bucket={bucket()} onClose={() => setAccess(false)} />
      </Show>
      <Show when={editing() === "tags"}>
        <TagsDialog
          title={`Tags of ${bucket()}`}
          tags={bucketTags()}
          save={(tags) => api.setBucketTags(bucket(), tags)}
          changed={loadVersioning}
          onClose={() => setEditing(undefined)}
        />
      </Show>
      <Show when={editing() === "cors"}>
        <CorsDialog bucket={bucket()} onClose={() => setEditing(undefined)} />
      </Show>
      <Show when={loaded()} fallback={<Loading error={error()} />}>
        <Panel>
          <Table
            count={entries().length}
            empty={prefix() ? "Nothing under this prefix." : "This bucket is empty."}
            columns={["Name", { label: "Size", num: true }, { label: "ETag", num: true }, "Last modified", ""]}
          >
            <For each={entries()}>
              {(e) =>
                e.kind === "prefix" ? (
                  <tr>
                    <td class="key">
                      <A href={bucketUrl(bucket(), e.prefix, deleted())}>📁 {e.prefix.slice(prefix().length)}</A>
                    </td>
                    <td class="num">{bytes(e.bytes)}</td>
                    <td class="num subtle">{num(e.objects)} objects</td>
                    <td>{date(e.last_modified)}</td>
                    <td />
                  </tr>
                ) : (
                  <tr>
                    <td class="key">
                      <A href={objectUrl(bucket(), e.key)}>{e.key.slice(prefix().length)}</A>{" "}
                      <Show when={e.delete_marker}>
                        <Badge tone="warn">deleted</Badge>
                      </Show>
                      <Show when={e.lost}>
                        <Badge tone="bad">lost data</Badge>
                      </Show>
                    </td>
                    <td class="num">{e.delete_marker ? "–" : bytes(e.size)}</td>
                    <td class="num mono subtle small">{e.etag ?? ""}</td>
                    <td>{date(e.last_modified)}</td>
                    <td class="actions">
                      <A class="button small" href={objectUrl(bucket(), e.key)}>
                        Details
                      </A>
                      <Show when={!e.delete_marker}>
                        <a class="button small" href={downloadUrl(bucket(), e.key)}>
                          Download
                        </a>
                        <button class="small danger" onClick={() => remove(e.key)}>
                          Delete
                        </button>
                      </Show>
                    </td>
                  </tr>
                )
              }
            </For>
          </Table>
          <Show when={next()}>
            <div class="toolbar">
              <button onClick={() => load(next()!)}>Load more</button>
            </div>
          </Show>
        </Panel>
      </Show>
    </>
  );
}

/** A starting point for a bucket's policy: anyone may read what's under
 * `public/`. */
const POLICY_TEMPLATE = (bucket: string) => `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${bucket}/public/*"
    }
  ]
}`;

/** The public access block's flags, as the dialog shows them. */
const FLAGS: { key: keyof PublicAccessBlock; label: string; note: string }[] = [
  { key: "block_public_policy", label: "Block public policies", note: "A policy that makes the bucket public is refused." },
  {
    key: "restrict_public_buckets",
    label: "Restrict public buckets",
    note: "A public policy allows unsigned requests nothing; the cluster's users keep what it allows them.",
  },
  { key: "block_public_acls", label: "Block public ACLs", note: "Kept for S3 clients: Cairn refuses every ACL but private anyway." },
  { key: "ignore_public_acls", label: "Ignore public ACLs", note: "Likewise." },
];

/** A bucket's policy and public access block, to view and change. The
 * server checks the policy as S3 does, and says what's wrong. */
function AccessDialog(props: { bucket: string; onClose: () => void }) {
  let dialog!: HTMLDialogElement;
  const [access, setAccess] = createSignal<BucketAccess>();
  const [block, setBlock] = createSignal<PublicAccessBlock>({
    block_public_acls: false,
    ignore_public_acls: false,
    block_public_policy: false,
    restrict_public_buckets: false,
  });
  const [document, setDocument] = createSignal("");
  const [error, setError] = createSignal<string>();
  const load = async () => {
    try {
      const a = await api.bucketAccess(props.bucket);
      setAccess(a);
      if (a.public_access_block) setBlock({ ...a.public_access_block });
      setDocument(a.policy ? pretty(a.policy) : POLICY_TEMPLATE(props.bucket));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  onMount(() => {
    dialog.showModal();
    load();
  });
  const run = async (fn: () => Promise<unknown>, done: string) => {
    setError(undefined);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(done);
    await load();
  };
  const saveBlock = () => run(() => api.putPublicAccessBlock(props.bucket, block()), `Saved the public access block of ${props.bucket}`);
  const removeBlock = () => {
    if (!confirm(`Remove the public access block of "${props.bucket}"? Only the cluster's will apply.`)) return;
    run(() => api.deletePublicAccessBlock(props.bucket), `Removed the public access block of ${props.bucket}`);
  };
  const savePolicy = () => run(() => api.putBucketPolicy(props.bucket, document()), `Saved the policy of ${props.bucket}`);
  const removePolicy = () => {
    if (!confirm(`Delete the policy of "${props.bucket}"?`)) return;
    run(() => api.deleteBucketPolicy(props.bucket), `Deleted the policy of ${props.bucket}`);
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <h2>
        Access to <span class="mono">{props.bucket}</span>
      </h2>
      <Show when={access()} fallback={<Loading error={error()} />}>
        {(a) => (
          <>
            <h3>Users with access</h3>
            <p class="subtle small">
              The account's users whose own policies (attached and inline; see Users and Policies) allow them something
              on the whole bucket. Access only to a prefix, or under conditions, isn't shown; the bucket policy below
              may allow more, and its Deny statements win over all of it.
            </p>
            <Table count={a().users.length} empty="No one, by their own policies." columns={["User", "May"]}>
              <For each={a().users}>
                {(u) => (
                  <tr>
                    <td class="mono">{u.user}</td>
                    <td>
                      <For each={u.levels}>{(l) => <span class="chip">{l}</span>}</For>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
            <h3>Public access block</h3>
            <p class="subtle small">
              <Show when={a().public_access_block} fallback="The bucket has no block of its own: only the cluster's applies.">
                The bucket's own block. The cluster's applies as well
                {a().cluster.block_public_policy || a().cluster.restrict_public_buckets ? " (it has some on)" : " (it has none on)"}.
              </Show>
            </p>
            <For each={FLAGS}>
              {(f) => (
                <div>
                  <label class="check" title={f.note}>
                    <input
                      type="checkbox"
                      checked={block()[f.key]}
                      onChange={(e) => setBlock({ ...block(), [f.key]: e.currentTarget.checked })}
                    />
                    {f.label}
                  </label>{" "}
                  <span class="subtle small">{f.note}</span>
                </div>
              )}
            </For>
            <div class="buttons">
              <Show when={a().public_access_block}>
                <button type="button" class="danger" onClick={removeBlock}>
                  Remove block
                </button>
              </Show>
              <button type="button" class="primary" onClick={saveBlock}>
                Save block
              </button>
            </div>
            <h3>
              Bucket policy{" "}
              <Show when={a().public}>
                <Badge tone="bad">public</Badge>
              </Show>
            </h3>
            <p class="subtle small">
              IAM's policy language, as a bucket policy: each statement names its Principal (
              <span class="mono">"*"</span> is anyone, unsigned requests too; a user is{" "}
              <span class="mono">arn:aws:iam::ACCOUNT:user/NAME</span>); Resource is the bucket or its objects.
              <Show when={!a().policy}> It has none; this is an example.</Show>
            </p>
            <textarea
              class="policy"
              aria-label="Bucket policy"
              spellcheck={false}
              value={document()}
              onInput={(e) => setDocument(e.currentTarget.value)}
            />
            <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
            <div class="buttons">
              <Show when={a().policy}>
                <button type="button" class="danger" onClick={removePolicy}>
                  Delete policy
                </button>
              </Show>
              <button type="button" onClick={() => dialog.close()}>
                Close
              </button>
              <button type="button" class="primary" onClick={savePolicy}>
                Save policy
              </button>
            </div>
          </>
        )}
      </Show>
    </dialog>
  );
}

/** How many versions the API lists at most. */
const MAX_VERSIONS = 200;

export function ObjectPage() {
  const params = useParams();
  const [search] = useSearchParams();
  const bucket = () => params.bucket ?? "";
  const key = () => (typeof search.key === "string" ? search.key : "");
  const data = poll(() => Promise.all([api.object(bucket(), key())]));
  const [tagging, setTagging] = createSignal<{ version: string; tags: { key: string; value: string }[] }>();
  const removeVersion = async (version: string) => {
    if (!confirm(`Delete version ${version} of "${key()}" for good?`)) return;
    if (await act(() => api.deleteObject(bucket(), key(), version), `Deleted version ${version}`)) data.refresh();
  };
  createEffect(on([bucket, key], () => data.refresh(), { defer: true }));
  const prefix = () => key().slice(0, key().lastIndexOf("/") + 1);

  return (
    <>
      <Show when={tagging()}>
        {(t) => (
          <TagsDialog
            title={`Tags of ${key()} (version ${t().version})`}
            tags={t().tags}
            save={(tags) => api.setObjectTags(bucket(), key(), t().version, tags)}
            changed={data.refresh}
            onClose={() => setTagging(undefined)}
          />
        )}
      </Show>
      <h1>Object</h1>
      <Crumbs bucket={bucket()} prefix={prefix()} />
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => {
          const obj = () => d()[0];
          return (
            <>
              <Panel>
                <dl class="kv">
                  <dt>Bucket</dt>
                  <dd>{obj().bucket}</dd>
                  <dt>Key</dt>
                  <dd class="mono">{obj().key}</dd>
                  <dt>Versions</dt>
                  <dd>
                    {num(obj().versions.length)}
                    {obj().versions.length >= MAX_VERSIONS ? ` (showing the newest ${MAX_VERSIONS})` : ""}
                  </dd>
                </dl>
              </Panel>
              <Show when={obj().versions.length} fallback={<Panel><p class="empty">No such key.</p></Panel>}>
                <For each={obj().versions}>
                  {(v) => (
                    <div class={"version" + (v.latest ? " latest" : "")}>
                      <div class="version-head">
                        {v.latest ? <Badge tone="accent">current</Badge> : <Badge>older</Badge>}
                        <Show when={v.delete_marker}>
                          <Badge tone="warn">delete marker</Badge>
                        </Show>
                        <Show when={v.lost_bytes}>
                          <A href="/integrity" class="badge-link">
                            <Badge tone="bad">{bytes(v.lost_bytes)} lost</Badge>
                          </A>
                        </Show>
                        <span class="mono">version {v.version_id}</span>
                        <span class="subtle">{date(v.last_modified)}</span>
                        <span class="spacer" />
                        <Show when={!v.delete_marker}>
                          <a class="button small" href={downloadUrl(obj().bucket, obj().key, v.version_id)}>
                            Download
                          </a>
                        </Show>
                        <Show when={!v.delete_marker}>
                          <button class="small" onClick={() => setTagging({ version: v.version_id, tags: v.tags })}>
                            Edit tags
                          </button>
                        </Show>
                        <button class="small danger" onClick={() => removeVersion(v.version_id)}>
                          Delete version
                        </button>
                      </div>
                      <Show when={!v.delete_marker}>
                        <dl class="kv">
                          <dt>Size</dt>
                          <dd>
                            {bytes(v.size)} ({num(v.size)} bytes)
                          </dd>
                          <dt>ETag</dt>
                          <dd class="mono">{v.etag}</dd>
                          <dt>Content type</dt>
                          <dd>{v.content_type}</dd>
                          <dt>Encryption</dt>
                          <dd>
                            <Show when={v.encryption} fallback="none">
                              {(e) => (
                                <Switch fallback={e().kind}>
                                  <Match when={e().kind === "SSE-C"}>SSE-C (with its client's key)</Match>
                                  <Match when={e().kind === "SSE-KMS" || e().kind === "SSE-S3"}>
                                    {e().kind === "SSE-S3" ? "SSE-S3 with Cairn's key " : "SSE-KMS with key "}
                                    <span class="mono">{e().kms_key_id}</span>
                                    {e().kms_key_version != null ? `, version ${e().kms_key_version}` : ""}
                                    <Show when={e().kms_context}>
                                      {(c) => (
                                        <div class="subtle">
                                          context <span class="mono">{c()}</span>
                                        </div>
                                      )}
                                    </Show>
                                  </Match>
                                </Switch>
                              )}
                            </Show>
                          </dd>
                          <dt>Tags</dt>
                          <dd>
                            <TagList tags={v.tags} />
                          </dd>
                        </dl>
                      </Show>
                    </div>
                  )}
                </For>
              </Show>
            </>
          );
        }}
      </Show>
    </>
  );
}
