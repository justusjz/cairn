// The cluster's backup, for operators, as `cairn backup` has it (see
// `src/backup.rs`, `src/console/cluster.rs`): where it goes, how far it's
// got, turning it on, changing or off, and running a cycle now. Its key
// isn't shown: `cairn backup key` on a node prints it.

import { For, Show, createSignal, onMount } from "solid-js";
import { type BackupStatus, api } from "../api";
import { Badge, Card, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { bytes, duration, num } from "../format";

/** An age in seconds, as "… ago". */
const ago = (secs: number | null | undefined) => (secs == null ? "never" : `${duration(secs)} ago`);

/** Seconds as the API takes durations: `5m`, `7d`, …. */
function spell(secs: number): string {
  for (const [unit, size] of [
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
  ] as const) {
    if (secs >= size && secs % size === 0) return `${secs / size}${unit}`;
  }
  return `${secs}s`;
}

/** Bytes as the API takes sizes: `256MiB`, …. */
function spellSize(n: number): string {
  for (const [unit, size] of [
    ["GiB", 1 << 30],
    ["MiB", 1 << 20],
  ] as const) {
    if (n >= size && n % size === 0) return `${n / size}${unit}`;
  }
  return `${n}B`;
}

export default function Backup() {
  const data = poll(() => api.backup(), 10000);
  const [editing, setEditing] = createSignal(false);
  const run = async (base: boolean) => {
    if (
      await act(
        () => api.runBackup(base),
        base ? "A base, then a cycle, runs within seconds" : "A cycle runs within seconds",
      )
    )
      data.refresh();
  };
  const disable = async () => {
    if (!confirm("Turn the backup off? What's in the bucket stays, and turning it back on there carries on.")) return;
    if (await act(() => api.disableBackup(), "The backup is off")) data.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Backup</h1>
        <Show when={data.data()}>
          {(d) => (
            <div class="buttons">
              <Show
                when={d().status?.enabled}
                fallback={
                  <button class="primary" onClick={() => setEditing(true)}>
                    Turn on…
                  </button>
                }
              >
                <button onClick={() => run(false)}>Run now</button>
                <button onClick={() => run(true)}>Run with a new base</button>
                <button onClick={() => setEditing(true)}>Change…</button>
                <button class="danger" onClick={disable}>
                  Turn off
                </button>
              </Show>
            </div>
          )}
        </Show>
      </div>
      <p class="subtle small">
        The backup copies the database and every object's data, encrypted, to a bucket of another S3 service: a cycle
        ships what changed every interval, and a new cluster can be restored from it with nothing else (
        <span class="mono">cairn restore</span>). A restore needs the backup's key, which isn't shown here: print it
        with <span class="mono">cairn backup key</span> on a node, and keep it apart from the cluster. The KMS's keys
        aren't backed up.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Show
            when={d().status}
            fallback={
              <Panel title="Not set up">
                <p class="subtle">Nothing is backed up yet. Turn the backup on to choose where to.</p>
              </Panel>
            }
          >
            {(s) => <View status={s()} />}
          </Show>
        )}
      </Show>
      <Show when={editing()}>
        <BackupDialog
          status={data.data()?.status ?? undefined}
          onClose={() => setEditing(false)}
          changed={data.refresh}
        />
      </Show>
    </>
  );
}

function View(props: { status: BackupStatus }) {
  const s = () => props.status;
  return (
    <>
      <div class="cards">
        <Card
          label="Backup"
          value={s().enabled ? "on" : "off"}
          note={`every ${duration(s().interval)}, keeping what's unneeded ${duration(s().retention)}`}
          tone={s().enabled ? "ok" : "warn"}
        />
        <Card
          label="Last journal"
          value={ago(s().journal_age)}
          note={`journal ${num(s().journal)} · checked ${ago(s().checked_age)}`}
        />
        <Card
          label="Last base"
          value={ago(s().base_age)}
          note={s().base_age == null ? "nothing can be restored until one is complete" : bytes(s().base_size)}
          tone={s().base_age == null ? "warn" : ""}
        />
        <Card label="Changes waiting" value={num(s().changes)} note="captured, shipped by the next cycle" />
      </div>
      <Show when={s().last_error}>
        <Panel title="Last error" note={ago(s().last_error_age)}>
          <p class="error-text">{s().last_error}</p>
        </Panel>
      </Show>
      <div class="grid cols-2">
        <Panel title="Where">
          <Table count={1} columns={["", ""]}>
            <tr>
              <td>Bucket</td>
              <td class="mono">
                s3://{s().bucket}/{s().prefix}
              </td>
            </tr>
            <tr>
              <td>Endpoint</td>
              <td class="mono">
                {s().endpoint}
                <div class="subtle small">
                  {s().region}
                  {s().path_style ? " · path-style" : ""}
                </div>
              </td>
            </tr>
            <tr>
              <td>Access key</td>
              <td class="mono">{s().access_key_id}</td>
            </tr>
            <tr>
              <td>Packs</td>
              <td>{bytes(s().pack_size)}</td>
            </tr>
          </Table>
        </Panel>
        <Panel title="What it holds">
          <Table
            count={s().objects.length}
            empty="Nothing yet: the first cycle takes a base."
            columns={["Kind", { label: "Objects", num: true }, { label: "Bytes", num: true }, ""]}
          >
            <For each={s().objects}>
              {(o) => (
                <tr>
                  <td>{o.kind === "tier" ? "in tiers (not copied)" : `${o.kind}s`}</td>
                  <td class="num">{num(o.count)}</td>
                  <td class="num">{bytes(o.bytes)}</td>
                  <td class="subtle small">
                    {o.unneeded > 0 ? `${num(o.unneeded)} unneeded, kept for the retention` : ""}
                  </td>
                </tr>
              )}
            </For>
          </Table>
          <Show when={s().building}>
            {(b) => (
              <p class="small">
                <Badge tone="accent">building a base</Badge> table {num(b().table)} of {num(b().tables)} (
                <span class="mono">{b().name}</span>), {num(b().chunks)} chunks, {bytes(b().bytes)} so far
              </p>
            )}
          </Show>
          <Show when={s().backfill != null}>
            <p class="small">
              <Badge tone="warn">copying</Badge> the data from before the backup: {num(s().backfill)} parts to go
            </p>
          </Show>
        </Panel>
      </div>
    </>
  );
}

/** Turns the backup on (where it was, if it was set up), or changes it. */
function BackupDialog(props: { status?: BackupStatus; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const s = props.status;
  const [endpoint, setEndpoint] = createSignal(s?.endpoint ?? "");
  const [region, setRegion] = createSignal(s?.region ?? "");
  const [bucket, setBucket] = createSignal(s?.bucket ?? "");
  const [prefix, setPrefix] = createSignal(s?.prefix ?? "");
  const [pathStyle, setPathStyle] = createSignal(s?.path_style ?? false);
  const [keyId, setKeyId] = createSignal(s?.access_key_id ?? "");
  const [secret, setSecret] = createSignal("");
  const [every, setEvery] = createSignal(s ? spell(s.interval) : "5m");
  const [retention, setRetention] = createSignal(s ? spell(s.retention) : "7d");
  const [packSize, setPackSize] = createSignal(s ? spellSize(s.pack_size) : "256MiB");
  const [key, setKey] = createSignal("");
  const [error, setError] = createSignal<string>();
  const trimmed = (p: string) => p.replace(/^\/+|\/+$/g, "");
  /** Whether it's to back up somewhere else than it did: a new backup. */
  const moved = () =>
    !!s &&
    (endpoint().trim().replace(/\/+$/, "") !== s.endpoint ||
      bucket().trim() !== s.bucket ||
      trimmed(prefix()) !== trimmed(s.prefix));
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      const result = await api.enableBackup({
        endpoint: endpoint().trim(),
        region: region().trim() || null,
        bucket: bucket().trim(),
        prefix: prefix().trim(),
        path_style: pathStyle(),
        access_key_id: keyId().trim(),
        secret_access_key: secret() || null,
        key: key().trim() || null,
        interval: every(),
        retention: retention(),
        pack_size: packSize(),
      });
      toast(`Backing up to ${result.location}`);
      if (result.new_key)
        toast("A new key was made: print it with cairn backup key on a node, and keep it apart from the cluster", true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{s?.enabled ? "Change the backup" : "Turn the backup on"}</h2>
        <label class="field">
          Endpoint
          <input
            type="url"
            required
            value={endpoint()}
            onInput={(e) => setEndpoint(e.currentTarget.value)}
            placeholder="https://s3.eu-central-1.amazonaws.com"
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
        <label class="field">
          Bucket (turn versioning on for it, so that it keeps what a mistake deletes)
          <input type="text" required value={bucket()} onInput={(e) => setBucket(e.currentTarget.value)} />
        </label>
        <label class="field">
          Prefix (the backup's own: nothing may be there yet)
          <input type="text" value={prefix()} onInput={(e) => setPrefix(e.currentTarget.value)} placeholder="cairn/" />
        </label>
        <label class="check">
          <input type="checkbox" checked={pathStyle()} onChange={(e) => setPathStyle(e.currentTarget.checked)} />
          Path-style addressing (host/bucket/key), as most services but AWS need
        </label>
        <label class="field">
          Access key ID
          <input type="text" required value={keyId()} onInput={(e) => setKeyId(e.currentTarget.value)} />
        </label>
        <label class="field">
          Secret access key {s ? "(empty: keep it, for the same endpoint and access key ID)" : ""}
          <input
            type="password"
            autocomplete="off"
            required={!s}
            value={secret()}
            onInput={(e) => setSecret(e.currentTarget.value)}
          />
        </label>
        <div class="form-row">
          <label class="field">
            Interval (the most a restore can lose)
            <input type="text" required value={every()} onInput={(e) => setEvery(e.currentTarget.value)} />
          </label>
          <label class="field">
            Retention (how far back a restore can go)
            <input type="text" required value={retention()} onInput={(e) => setRetention(e.currentTarget.value)} />
          </label>
          <label class="field">
            Pack size
            <input type="text" required value={packSize()} onInput={(e) => setPackSize(e.currentTarget.value)} />
          </label>
        </div>
        <label class="field">
          Key of your own (base64, 32 bytes; empty: the backup keeps its key, or gets a new one)
          <input type="password" autocomplete="off" value={key()} onInput={(e) => setKey(e.currentTarget.value)} />
        </label>
        <Show when={moved()}>
          <p class="error-text">
            That's somewhere else than the backup was: a new backup starts there, from a base, with a new key unless you
            give one.
          </p>
        </Show>
        <p class="subtle small">
          Saving checks that the bucket is reachable{s ? "" : " and the prefix empty"}. Durations are like 30s, 5m, 12h
          or 7d; sizes like 256MiB.
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {s?.enabled ? "Save" : "Turn on"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
