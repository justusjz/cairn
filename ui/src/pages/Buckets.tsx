import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { For, Show, createEffect, createSignal, on } from "solid-js";
import { type Entry, api, downloadUrl } from "../api";
import { Badge, LiveDot, Loading, Panel, Table, act, poll } from "../components/ui";
import { bytes, date, num } from "../format";

const enc = encodeURIComponent;

export function bucketUrl(bucket: string, prefix = "", deleted = false) {
  const query = new URLSearchParams();
  if (prefix) query.set("prefix", prefix);
  if (deleted) query.set("deleted", "1");
  const q = query.toString();
  return `/buckets/${enc(bucket)}` + (q ? "?" + q : "");
}

export function objectUrl(bucket: string, key: string) {
  return `/buckets/${enc(bucket)}/object?key=${enc(key)}`;
}

export function BucketList() {
  const buckets = poll(api.buckets);
  const [name, setName] = createSignal("");
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    if (await act(() => api.createBucket(n), `Created bucket ${n}`)) {
      setName("");
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
                { label: "Objects", num: true },
                { label: "Size", num: true },
                { label: "Older versions", num: true },
                { label: "Uploads", num: true },
                { label: "Roles", num: true },
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
                      {b.versioning === "enabled" ? (
                        <Badge tone="accent">versioned</Badge>
                      ) : b.versioning === "suspended" ? (
                        <Badge tone="warn">suspended</Badge>
                      ) : (
                        <Badge>unversioned</Badge>
                      )}
                    </td>
                    <td class="num">{num(b.objects)}</td>
                    <td class="num">{bytes(b.bytes)}</td>
                    <td class="num">{b.versions > b.objects ? `${num(b.versions - b.objects)} · ${bytes(b.version_bytes - b.bytes)}` : "–"}</td>
                    <td class="num">{num(b.uploads)}</td>
                    <td class="num">{num(b.roles)}</td>
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

  // Counts the listings started, so that a page of an old one is dropped.
  let listing = 0;
  const load = async (after: string) => {
    const current = listing;
    try {
      const page = await api.objects(bucket(), prefix(), after, deleted());
      if (current !== listing) return;
      setEntries((e) => [...e, ...page.entries]);
      setNext(page.next);
      setLoaded(true);
    } catch (e) {
      if (current === listing) setError((e as Error).message);
    }
  };
  // Start over whenever the listing's bucket, prefix or filter changes.
  createEffect(
    on([bucket, prefix, deleted], () => {
      listing++;
      setEntries([]);
      setNext(null);
      setLoaded(false);
      setError(undefined);
      load("");
    }),
  );

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
                "prefix" in e ? (
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
  const data = poll(() => Promise.all([api.object(bucket(), key()), api.cluster()]));
  createEffect(on([bucket, key], () => data.refresh(), { defer: true }));
  const prefix = () => key().slice(0, key().lastIndexOf("/") + 1);

  return (
    <>
      <h1>Object</h1>
      <Crumbs bucket={bucket()} prefix={prefix()} />
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => {
          const obj = () => d()[0];
          const cluster = () => d()[1];
          const node = (id: number) => cluster().nodes.find((n) => n.id === id);
          const liveCopies = (ids: number[]) => ids.filter((id) => node(id)?.live).length;
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
                        <span class="mono">version {v.version_id}</span>
                        <span class="subtle">{date(v.last_modified)}</span>
                        <span class="spacer" />
                        <Show when={!v.delete_marker}>
                          <a class="button small" href={downloadUrl(obj().bucket, obj().key, v.version_id)}>
                            Download
                          </a>
                        </Show>
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
                        </dl>
                        <div class="parts">
                          <Table
                            count={v.parts.length}
                            empty="No parts."
                            columns={[{ label: "Part", num: true }, { label: "Size", num: true }, "Blob", "Replicas", "CRC64/NVME"]}
                          >
                            <For each={v.parts}>
                              {(p) => (
                                <tr>
                                  <td class="num">{p.number}</td>
                                  <td class="num">{bytes(p.size)}</td>
                                  <td class="mono small">
                                    {p.blob_id}
                                    <div class="subtle">
                                      at {num(p.blob_offset)} of {bytes(p.blob_size)}
                                      {p.blob_size > p.size ? " (packed)" : ""}
                                    </div>
                                  </td>
                                  <td>
                                    <Show when={p.nodes.length} fallback={<Badge tone="bad">no copies</Badge>}>
                                      <For each={p.nodes}>
                                        {(id) => (
                                          <span class="chip" title={node(id)?.peer_url ?? ""}>
                                            <LiveDot live={!!node(id)?.live} />#{id}
                                          </span>
                                        )}
                                      </For>
                                    </Show>
                                    <Show when={liveCopies(p.nodes) < cluster().replication_factor}>
                                      {" "}
                                      <Badge tone="warn">under-replicated</Badge>
                                    </Show>
                                  </td>
                                  <td class="mono small">{p.crc64nvme ?? "–"}</td>
                                </tr>
                              )}
                            </For>
                          </Table>
                        </div>
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
