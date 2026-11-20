// What the Storage page changes of the cluster's configuration, as the CLI's
// `cairn class`, `cairn tier` and `cairn remote` do (see
// `src/console/cluster.rs`): storage classes, the remote tiers classes keep
// their data in, and the other clusters buckets replicate to. Secrets are
// taken, never shown: a change that leaves one empty keeps it.

import { For, Show, createResource, createSignal, onMount } from "solid-js";
import { type Cluster, type ReplicationRemote, type Storage, type Tier, api } from "../api";
import { bytes, num } from "../format";
import { Badge, Panel, Table, act, poll, toast } from "./ui";

type Class = Storage["classes"][number];

/** The pools the nodes have, by their `--data-dir`s. */
function poolsOf(cluster: Cluster): string[] {
  const pools = new Set<string>();
  for (const n of cluster.nodes) for (const p of n.stats?.pools ?? []) pools.add(p.name);
  return [...pools].sort();
}

/** A whole number from a field, `null` if it's empty, or `undefined` if it
 * isn't one. */
function wholeOrNull(text: string): number | null | undefined {
  if (text.trim() === "") return null;
  const n = Number(text.trim());
  return Number.isInteger(n) ? n : undefined;
}

/** The reason a dialog's request failed, for it to show. */
const reason = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** A storage class to define, or to change (`class`): the pool or tier it
 * keeps its data in, its layout, and its rank. */
export function ClassDialog(props: { class?: Class; cluster: Cluster; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const c = props.class;
  const [tiers] = createResource(() => api.tiers());
  const [name, setName] = createSignal(c?.name ?? "");
  const [inTier, setInTier] = createSignal(!!c?.tier);
  const [pool, setPool] = createSignal(c && !c.tier ? c.pool : "");
  const [tier, setTier] = createSignal(c?.tier ?? "");
  // A tier's class goes by STANDARD's shards, which aren't its own.
  const own = c && !c.tier ? c : undefined;
  const [data, setData] = createSignal(own?.data_shards?.toString() ?? "");
  const [parity, setParity] = createSignal(own?.parity_shards?.toString() ?? "");
  const [rank, setRank] = createSignal(c?.rank?.toString() ?? "");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const [k, m, r] = [wholeOrNull(data()), wholeOrNull(parity()), wholeOrNull(rank())];
    if (k === undefined || m === undefined || r === undefined) {
      setError("Shards and rank are whole numbers, or empty.");
      return;
    }
    const body = inTier()
      ? { tier: tier(), rank: r }
      : { pool: pool().trim(), data_shards: k, parity_shards: m, rank: r };
    try {
      const result = await api.putStorageClass(name().trim(), body);
      toast(result.description);
      for (const warning of result.warnings) toast(warning, true);
    } catch (e) {
      setError(reason(e));
      return;
    }
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{c ? `Edit ${c.name}` : "New storage class"}</h2>
        <label class="field">
          Name (as clients send it in x-amz-storage-class)
          <input
            type="text"
            required
            disabled={!!c}
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            placeholder="STANDARD_IA"
          />
        </label>
        <div class="form-row">
          <label class="check">
            <input type="radio" name="place" checked={!inTier()} onChange={() => setInTier(false)} />
            In a pool of the nodes
          </label>
          <label class="check">
            <input
              type="radio"
              name="place"
              checked={inTier()}
              disabled={c?.name === "STANDARD"}
              onChange={() => setInTier(true)}
            />
            In a remote tier
          </label>
        </div>
        <Show
          when={inTier()}
          fallback={
            <>
              <label class="field">
                Pool (a node's --data-dir pool=path)
                <input
                  type="text"
                  required
                  list="known-pools"
                  value={pool()}
                  onInput={(e) => setPool(e.currentTarget.value)}
                  placeholder="hdd"
                />
                <datalist id="known-pools">
                  <For each={poolsOf(props.cluster)}>{(p) => <option value={p} />}</For>
                </datalist>
              </label>
              <label class="field">
                Data shards (empty: the cluster's setting)
                <input type="text" inputmode="numeric" value={data()} onInput={(e) => setData(e.currentTarget.value)} />
              </label>
              <label class="field">
                Parity shards (empty: the cluster's setting)
                <input
                  type="text"
                  inputmode="numeric"
                  value={parity()}
                  onInput={(e) => setParity(e.currentTarget.value)}
                />
              </label>
              <p class="subtle small">
                Blobs over 64 MiB are erasure-coded into the data shards (1 keeps them replicated); parity shards are
                the nodes every blob survives losing. Either takes as many nodes with the pool as shards.
              </p>
            </>
          }
        >
          <label class="field">
            Tier
            <select required value={tier()} onChange={(e) => setTier(e.currentTarget.value)}>
              <option value="" disabled>
                {tiers()?.length === 0 ? "No tiers yet: add one below" : "Choose a tier"}
              </option>
              <For each={tiers() ?? []}>{(t) => <option value={t.name}>{t.name}</option>}</For>
            </select>
          </label>
          <p class="subtle small">
            Its data is written into STANDARD's pool and layout first, and the packer moves it into the tier.
          </p>
        </Show>
        <label class="field">
          Rank (empty: none; STANDARD is 0)
          <input type="text" inputmode="numeric" value={rank()} onInput={(e) => setRank(e.currentTarget.value)} />
        </label>
        <p class="subtle small">
          The warmest class ranks highest. Lifecycle rules move objects into lower ranked classes, and a class stands in
          for those below it. No two classes share a rank. A change applies to new objects within a heartbeat; the
          packer rewrites existing data over time.
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {c ? "Save" : "Add class"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** Deletes a class, once asked. */
export async function deleteClass(c: Class, changed: () => void) {
  if (!confirm(`Delete the storage class ${c.name}? Only a class that holds nothing can go.`)) return;
  if (await act(() => api.deleteStorageClass(c.name), `Deleted ${c.name}`)) changed();
}

/** The remote tiers (`cairn tier`): buckets of other S3 services that
 * storage classes keep their data in. */
export function TiersPanel(props: { changed: () => void }) {
  const data = poll(() => api.tiers(), 30000);
  /** The tier being edited, or `null` for a new one. */
  const [editing, setEditing] = createSignal<Tier | null>();
  const changed = () => {
    data.refresh();
    props.changed();
  };
  const remove = async (t: Tier) => {
    if (!confirm(`Delete the tier ${t.name}? Only a tier no class uses, and that holds nothing, can go.`)) return;
    if (await act(() => api.deleteTier(t.name), `Deleted ${t.name}`)) changed();
  };
  return (
    <Panel
      title="Remote tiers"
      note="buckets of other S3 services that classes keep their data in · encrypted with a key of the tier's own"
    >
      <div class="buttons">
        <button onClick={() => setEditing(null)}>Add tier…</button>
      </div>
      <Table
        count={data.data()?.length ?? 0}
        empty={data.error() ?? "None: every class keeps its data on the nodes."}
        columns={[
          "Tier",
          "Where",
          "Access key",
          "Classes",
          { label: "Objects", num: true },
          { label: "Bytes", num: true },
          "",
        ]}
      >
        <For each={data.data()}>
          {(t) => (
            <tr>
              <td class="mono">
                {t.name}
                <Show when={!t.writable}>
                  <div>
                    <Badge tone="warn">read-only</Badge>
                  </div>
                </Show>
              </td>
              <td class="mono small">
                s3://{t.bucket}/{t.prefix}
                <div class="subtle">
                  {t.endpoint} · {t.region}
                  {t.path_style ? " · path-style" : ""}
                  {t.remote_class ? ` · as ${t.remote_class}` : ""}
                </div>
              </td>
              <td class="mono small">{t.access_key_id}</td>
              <td class="mono small">{t.classes.join(", ") || "–"}</td>
              <td class="num">{num(t.objects)}</td>
              <td class="num">
                {bytes(t.bytes)}
                <Show when={t.garbage > 0}>
                  <div class="subtle small">{num(t.garbage)} objects to delete</div>
                </Show>
              </td>
              <td class="actions">
                <button class="small" onClick={() => setEditing(t)}>
                  Edit
                </button>
                <button class="small danger" onClick={() => remove(t)}>
                  Delete
                </button>
              </td>
            </tr>
          )}
        </For>
      </Table>
      <Show when={editing() !== undefined}>
        <TierDialog tier={editing() ?? undefined} onClose={() => setEditing(undefined)} changed={changed} />
      </Show>
    </Panel>
  );
}

/** A tier to add, or to change (`tier`): its credentials, the class its
 * objects are written in there, and whether this cluster may write to it. */
function TierDialog(props: { tier?: Tier; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const t = props.tier;
  const [name, setName] = createSignal(t?.name ?? "");
  const [location, setLocation] = createSignal({ endpoint: "", region: "", bucket: "", prefix: "", path_style: false });
  const [keyId, setKeyId] = createSignal(t?.access_key_id ?? "");
  const [secret, setSecret] = createSignal("");
  const [remoteClass, setRemoteClass] = createSignal(t?.remote_class ?? "");
  const [writable, setWritable] = createSignal(t?.writable ?? true);
  const [error, setError] = createSignal<string>();
  const where = (field: "endpoint" | "region" | "bucket" | "prefix") => (e: { currentTarget: HTMLInputElement }) =>
    setLocation({ ...location(), [field]: e.currentTarget.value });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      if (t) {
        const result = await api.setTier(t.name, {
          writable: writable(),
          remote_class: remoteClass().trim(),
          access_key_id: keyId().trim(),
          secret_access_key: secret() || null,
        });
        for (const warning of result.warnings) toast(warning, true);
      } else {
        await api.addTier({
          name: name().trim(),
          ...location(),
          access_key_id: keyId().trim(),
          secret_access_key: secret(),
          remote_class: remoteClass().trim() || null,
        });
      }
    } catch (e) {
      setError(reason(e));
      return;
    }
    toast(t ? `Saved ${t.name}` : `Added ${name().trim()}: keep a class's data there with Edit on the class`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{t ? `Edit ${t.name}` : "New remote tier"}</h2>
        <Show
          when={!t}
          fallback={
            <p class="subtle small mono">
              s3://{t!.bucket}/{t!.prefix} at {t!.endpoint}
            </p>
          }
        >
          <label class="field">
            Name (lowercase letters, digits, - and _)
            <input
              type="text"
              required
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              placeholder="archive"
            />
          </label>
          <label class="field">
            Endpoint
            <input
              type="url"
              required
              value={location().endpoint}
              onInput={where("endpoint")}
              placeholder="https://s3.eu-central-1.amazonaws.com"
            />
          </label>
          <label class="field">
            Region
            <input type="text" value={location().region} onInput={where("region")} placeholder="us-east-1" />
          </label>
          <label class="field">
            Bucket
            <input type="text" required value={location().bucket} onInput={where("bucket")} />
          </label>
          <label class="field">
            Prefix (the tier's own: nothing may be there yet)
            <input type="text" value={location().prefix} onInput={where("prefix")} placeholder="cairn/" />
          </label>
          <label class="check">
            <input
              type="checkbox"
              checked={location().path_style}
              onChange={(e) => setLocation({ ...location(), path_style: e.currentTarget.checked })}
            />
            Path-style addressing (host/bucket/key), as most services but AWS need
          </label>
        </Show>
        <label class="field">
          Access key ID
          <input type="text" required value={keyId()} onInput={(e) => setKeyId(e.currentTarget.value)} />
        </label>
        <label class="field">
          Secret access key {t ? "(empty: keep it)" : ""}
          <input
            type="password"
            autocomplete="off"
            required={!t}
            value={secret()}
            onInput={(e) => setSecret(e.currentTarget.value)}
          />
        </label>
        <label class="field">
          Storage class there (empty: the service's default)
          <input
            type="text"
            value={remoteClass()}
            onInput={(e) => setRemoteClass(e.currentTarget.value)}
            placeholder="STANDARD_IA"
          />
        </label>
        <Show when={t}>
          <label class="check">
            <input type="checkbox" checked={writable()} onChange={(e) => setWritable(e.currentTarget.checked)} />
            Writable: this cluster writes there, and deletes what it no longer needs
          </label>
          <p class="subtle small">
            A restored cluster's tiers are read-only, since the cluster it was restored from may still use them. Make
            one writable only once that cluster is gone for good.
          </p>
        </Show>
        <p class="subtle small">
          {t
            ? "New credentials are checked to reach the tier first."
            : "Adding checks that the tier is reachable and empty."}{" "}
          Its objects are encrypted with a key Cairn makes, which is in the database and its backup.
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {t ? "Save" : "Add tier"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** The replication remotes (`cairn remote`): other clusters' S3 endpoints,
 * which buckets' replication rules name buckets of. */
export function RemotesPanel() {
  const data = poll(() => api.replicationRemotes(), 30000);
  /** The remote being edited, or `null` for a new one. */
  const [editing, setEditing] = createSignal<ReplicationRemote | null>();
  const remove = async (r: ReplicationRemote) => {
    if (!confirm(`Delete the remote ${r.name}?`)) return;
    if (await act(() => api.deleteReplicationRemote(r.name), `Deleted ${r.name}`)) data.refresh();
  };
  return (
    <Panel title="Replication remotes" note="other clusters (Cairn, MinIO, RustFS) that buckets replicate to">
      <div class="buttons">
        <button onClick={() => setEditing(null)}>Add remote…</button>
      </div>
      <Table
        count={data.data()?.length ?? 0}
        empty={data.error() ?? "None: buckets replicate within the cluster only."}
        columns={["Remote", "Endpoint", "Access key", "Replicated to by", ""]}
      >
        <For each={data.data()}>
          {(r) => (
            <tr>
              <td>
                <span class="mono">{r.name}</span> <Badge>{r.kind}</Badge>
                <div class="subtle small mono">arn:cairn:replication::{r.name}:&lt;bucket&gt;</div>
              </td>
              <td class="mono small">
                {r.endpoint}
                <div class="subtle">
                  {r.region}
                  {r.path_style ? " · path-style" : ""}
                </div>
              </td>
              <td class="mono small">{r.access_key_id}</td>
              <td class="mono small">{r.buckets.join(", ") || <span class="subtle">no bucket</span>}</td>
              <td class="actions">
                <button class="small" onClick={() => setEditing(r)}>
                  Edit
                </button>
                <button class="small danger" disabled={r.buckets.length > 0} onClick={() => remove(r)}>
                  Delete
                </button>
              </td>
            </tr>
          )}
        </For>
      </Table>
      <Show when={editing() !== undefined}>
        <RemoteDialog remote={editing() ?? undefined} onClose={() => setEditing(undefined)} changed={data.refresh} />
      </Show>
    </Panel>
  );
}

/** A remote to add, or to change (`remote`). Its kind stays: the version IDs
 * it was sent are its kind's. */
function RemoteDialog(props: { remote?: ReplicationRemote; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const r = props.remote;
  const [name, setName] = createSignal(r?.name ?? "");
  const [kind, setKind] = createSignal(r?.kind ?? "cairn");
  const [endpoint, setEndpoint] = createSignal(r?.endpoint ?? "");
  const [region, setRegion] = createSignal(r?.region ?? "");
  const [pathStyle, setPathStyle] = createSignal(r?.path_style ?? false);
  const [keyId, setKeyId] = createSignal(r?.access_key_id ?? "");
  const [secret, setSecret] = createSignal("");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const common = { endpoint: endpoint().trim(), region: region().trim() || null, path_style: pathStyle() };
    try {
      if (r) {
        await api.setReplicationRemote(r.name, {
          ...common,
          access_key_id: keyId().trim(),
          secret_access_key: secret() || null,
        });
      } else {
        await api.addReplicationRemote({
          ...common,
          name: name().trim(),
          kind: kind(),
          access_key_id: keyId().trim(),
          secret_access_key: secret(),
        });
      }
    } catch (e) {
      setError(reason(e));
      return;
    }
    toast(r ? `Saved ${r.name}` : `Added ${name().trim()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{r ? `Edit ${r.name}` : "New replication remote"}</h2>
        <label class="field">
          Name (lowercase letters, digits, - and _)
          <input
            type="text"
            required
            disabled={!!r}
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            placeholder="dc2"
          />
        </label>
        <p class="subtle small">
          Replication rules name its buckets as{" "}
          <span class="mono">arn:cairn:replication::{name() || "<name>"}:&lt;bucket&gt;</span>. To take a configuration
          written for MinIO as it is, give the ID its ARNs have.
        </p>
        <label class="field">
          Kind
          <select disabled={!!r} value={kind()} onChange={(e) => setKind(e.currentTarget.value)}>
            <option value="cairn">Cairn</option>
            <option value="minio">MinIO</option>
            <option value="rustfs">RustFS</option>
          </select>
        </label>
        <label class="field">
          Endpoint
          <input
            type="url"
            required
            value={endpoint()}
            onInput={(e) => setEndpoint(e.currentTarget.value)}
            placeholder="https://s3.dc2.example.com"
          />
        </label>
        <label class="field">
          Region
          <input
            type="text"
            value={region()}
            onInput={(e) => setRegion(e.currentTarget.value)}
            placeholder="us-east-1"
          />
        </label>
        <label class="check">
          <input type="checkbox" checked={pathStyle()} onChange={(e) => setPathStyle(e.currentTarget.checked)} />
          Path-style addressing (host/bucket/key), as MinIO and RustFS usually are
        </label>
        <label class="field">
          Access key ID
          <input type="text" required value={keyId()} onInput={(e) => setKeyId(e.currentTarget.value)} />
        </label>
        <label class="field">
          Secret access key {r ? "(empty: keep it, for the same endpoint)" : ""}
          <input
            type="password"
            autocomplete="off"
            required={!r}
            value={secret()}
            onInput={(e) => setSecret(e.currentTarget.value)}
          />
        </label>
        <p class="subtle small">
          Its users' policies decide what may be written there: allow s3:ReplicateObject, s3:ReplicateTags and
          s3:ReplicateDelete (MinIO also wants s3:PutObject and s3:DeleteObject).
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {r ? "Save" : "Add remote"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
