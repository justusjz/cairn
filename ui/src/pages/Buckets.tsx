import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { For, Match, Show, Switch, createEffect, createSignal, on, onMount } from "solid-js";
import { type Bucket, type Entry, type PublicAccessBlock, api, downloadUrl } from "../api";
import { StorageClassSelect, VersionSettings, objectDetails } from "../components/BucketSettings";
import { TagsDialog } from "../components/Editors";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { bytes, date, num } from "../format";
import { ReplicationBadge, ReplicationQueue } from "./Replication";

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
 * block and its account's say. */
function PublicAccess(props: { bucket: Bucket }) {
  const either = (key: "restrict_public_buckets" | "block_public_policy") =>
    !!props.bucket.public_access_block?.[key] || !!props.bucket.account_public_access_block?.[key];
  const restricted = () => either("restrict_public_buckets");
  const blocked = () => either("block_public_policy");
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

const NO_BLOCK: PublicAccessBlock = {
  block_public_acls: false,
  ignore_public_acls: false,
  block_public_policy: false,
  restrict_public_buckets: false,
};

/** The account's public access block (S3 Control's), which every one of
 * its buckets gets too, whatever its own says: shown to whom may read it,
 * and changed by whom may set it. */
function AccountBlock(props: { changed: () => void }) {
  const block = poll(() => api.accountBlock(), 30000);
  const set = async (key: keyof PublicAccessBlock, on: boolean) => {
    const next = { ...(block.data() ?? NO_BLOCK), [key]: on };
    const label = key === "block_public_policy" ? "Blocking public policies" : "Restricting public buckets";
    if (await act(() => api.putAccountBlock(next), `${label} in every bucket: ${on ? "on" : "off"}`)) {
      block.refresh();
      props.changed();
    }
  };
  return (
    <Show when={!block.error() && block.data() !== undefined}>
      <div class="toolbar">
        <span class="subtle">For every bucket of this account:</span>
        <label class="check" title="Refuse bucket policies that make a bucket public, whatever its own block says">
          <input
            type="checkbox"
            checked={!!block.data()?.block_public_policy}
            onChange={(e) => set("block_public_policy", e.currentTarget.checked)}
          />
          Block public policies
        </label>
        <label class="check" title="Let no public bucket policy allow anyone outside the account, unsigned requests included, anything">
          <input
            type="checkbox"
            checked={!!block.data()?.restrict_public_buckets}
            onChange={(e) => set("restrict_public_buckets", e.currentTarget.checked)}
          />
          Restrict public buckets
        </label>
      </div>
    </Show>
  );
}

/** A new bucket: its name, and whether it has Object Lock. */
function NewBucketDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal("");
  const [objectLock, setObjectLock] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.createBucket(n, objectLock());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Created bucket ${n}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={create}>
        <h2>New bucket</h2>
        <input
          type="text"
          placeholder="bucket-name"
          aria-label="Bucket name"
          autocomplete="off"
          required
          value={name()}
          onInput={(e) => setName(e.currentTarget.value)}
        />
        <label class="check">
          <input type="checkbox" checked={objectLock()} onChange={(e) => setObjectLock(e.currentTarget.checked)} />
          Object Lock
        </label>
        <p class="subtle small">
          Keeps versions from being deleted for a retention period, or under a legal hold, as S3's Object Lock. It can't be
          disabled again, and the bucket stays versioned.
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Create bucket
          </button>
        </div>
      </form>
    </dialog>
  );
}

export function BucketList() {
  const buckets = poll(() => api.buckets());
  const [creating, setCreating] = createSignal(false);
  const remove = async (n: string) => {
    if (!confirm(`Delete bucket "${n}"? It must be empty.`)) return;
    if (await act(() => api.deleteBucket(n), `Deleted bucket ${n}`)) buckets.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Buckets</h1>
        <button class="primary" onClick={() => setCreating(true)}>
          New bucket
        </button>
      </div>
      <Show when={creating()}>
        <NewBucketDialog onClose={() => setCreating(false)} changed={buckets.refresh} />
      </Show>
      <AccountBlock changed={buckets.refresh} />
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
                      <Show when={b.default_kms_key} fallback={<span class="subtle">{b.default_encryption ?? "none"}</span>}>
                        {(key) => (
                          <span title="Writes that ask for no encryption of their own get SSE-KMS under this key">
                            SSE-KMS <span class="mono">{key()}</span>
                          </span>
                        )}
                      </Show>
                    </td>
                    <td>
                      <PublicAccess bucket={b} />
                    </td>
                    <td class="num">{num(b.objects)}</td>
                    <td class="num">{bytes(b.bytes)}</td>
                    <td class="num">{b.versions > b.objects ? `${num(b.versions - b.objects)} · ${bytes(b.version_bytes - b.bytes)}` : "–"}</td>
                    <td class="num">{num(b.uploads)}</td>
                    <td class="num">{num(b.users)}</td>
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
  const [uploading, setUploading] = createSignal<string>();
  // The storage class uploads are written in ("": STANDARD).
  const [uploadClass, setUploadClass] = createSignal("");
  /** Uploads the chosen files under the current prefix, one by one. */
  const upload = async (files: FileList | null) => {
    if (!files) return;
    for (const file of Array.from(files)) {
      const key = prefix() + file.name;
      setUploading(`Uploading ${file.name} (${bytes(file.size)})…`);
      const progress = (sent: number) =>
        setUploading(`Uploading ${file.name}: ${bytes(sent)} of ${bytes(file.size)} (${Math.floor((sent / file.size) * 100)}%)`);
      if (!(await act(() => api.upload(bucket(), key, file, progress, uploadClass()), `Uploaded ${key}`))) break;
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
        <StorageClassSelect label="Storage class of uploads" value={uploadClass()} onChange={setUploadClass} />
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

/** How many versions the API lists at most. */
const MAX_VERSIONS = 200;

export function ObjectPage() {
  const params = useParams();
  const [search] = useSearchParams();
  const bucket = () => params.bucket ?? "";
  const key = () => (typeof search.key === "string" ? search.key : "");
  const data = poll(() => Promise.all([api.object(bucket(), key())]));
  const details = objectDetails(bucket, key);
  const [tagging, setTagging] = createSignal<{ version: string; tags: { key: string; value: string }[] }>();
  const removeVersion = async (version: string) => {
    if (!confirm(`Delete version ${version} of "${key()}" for good?`)) return;
    if (await act(() => api.deleteObject(bucket(), key(), version), `Deleted version ${version}`)) data.refresh();
  };
  createEffect(on([bucket, key], () => data.refresh(), { defer: true }));
  createEffect(on([bucket, key], () => details.refresh(), { defer: true }));
  const changed = () => {
    data.refresh();
    details.refresh();
  };
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
              <ReplicationQueue bucket={obj().bucket} keyName={obj().key} />
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
                        <ReplicationBadge status={v.replication_status} />
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
                        <VersionSettings
                          bucket={obj().bucket}
                          objectKey={obj().key}
                          versionId={v.version_id}
                          latest={v.latest}
                          details={details.data()}
                          changed={changed}
                        />
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
