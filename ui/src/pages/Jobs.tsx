import { A } from "@solidjs/router";
import { For, Show, createMemo, createSignal } from "solid-js";
import { type Cluster, type Event, type Lifecycle, type LifecycleBucket, type Storage, api, statsError, statsOf } from "../api";
import { Badge, Card, LiveDot, Loading, Panel, Table, act, poll } from "../components/ui";
import { ago, bytes, date, duration, hex, now, num, pct } from "../format";

export default function Jobs() {
  const cluster = poll(api.cluster, 5000);
  // The catalog's backlog takes a scan, so it's refreshed less often.
  const storage = poll(api.storage, 30000);
  return (
    <Show when={cluster.data() && storage.data()} fallback={<Loading error={cluster.error() ?? storage.error()} />}>
      <View cluster={cluster.data()!} storage={storage.data()!} />
    </Show>
  );
}

function View(props: { cluster: Cluster; storage: Storage }) {
  const bl = () => props.storage.backlog;
  const b = () => props.storage.blobs;
  const pk = () => props.storage.packer;
  const events = createMemo(() => {
    const all: (Event & { node: number })[] = [];
    for (const n of props.cluster.nodes) {
      for (const e of statsOf(n)?.maintenance.events ?? []) all.push({ ...e, node: n.id });
    }
    return all.sort((x, y) => y.time - x.time).slice(0, 200);
  });
  const old = (t: number | null | undefined) => t != null && now() - t > 3600;

  return (
    <>
      <div class="page-head">
        <h1>Background jobs</h1>
        <span class="subtle small">Every node runs garbage collection, then packing, once a minute</span>
      </div>
      <div class="cards">
        <Card
          label="Packing now"
          value={num(bl().packing)}
          note={`${bytes(bl().packing_bytes)} in blobs leased by packing jobs`}
          tone={bl().packing ? "ok" : ""}
        />
        <Card
          label="To consolidate"
          value={num(bl().consolidate)}
          note={`${bytes(bl().consolidate_bytes)} in blobs ≤ ${bytes(pk().small_size)}; packed once ${bytes(pk().target_size)} or ${num(pk().max_sources)} blobs wait`}
        />
        <Card
          label="To compact"
          value={num(bl().compact)}
          note={`${bytes(bl().compact_garbage_bytes)} of garbage in blobs ≥ ${pct(pk().compact_threshold, 1)} garbage`}
        />
        <Card
          label="To code"
          value={num(bl().convert)}
          note={
            pk().data_shards > 1 && pk().parity_shards > 0
              ? `${bytes(bl().convert_bytes)} in replicated blobs > ${bytes(pk().small_size)}, ${duration(pk().cold_age_secs)} old; erasure-coded ${pk().data_shards}+${pk().parity_shards}${pk().coding ? ", one job per node and pass" : ", once as many nodes are live"}`
              : "erasure coding is off: set data-shards with cairn config"
          }
          tone={pk().data_shards > 1 && !pk().coding ? "warn" : ""}
        />
        <Card
          label="To move"
          value={num(bl().moves)}
          note={
            bl().repair_after > 0
              ? `shards on nodes being removed, or down for over ${bl().repair_after} min`
              : "shards on nodes being removed; a node that's down waits for cairn node remove"
          }
          tone={bl().moves ? "warn" : ""}
        />
        <Card label="Garbage log" value={num(bl().garbage_log)} note="deleted parts, folded on the next packer pass" />
        <Card
          label="Pending blobs"
          value={num(b().pending)}
          note={b().oldest_pending ? `oldest ${duration(now() - b().oldest_pending!)}; dropped after a day` : "uploads and packing jobs in progress"}
          tone={old(b().oldest_pending) ? "warn" : ""}
        />
        <Card
          label="Multipart uploads"
          value={num(bl().uploads)}
          note={bl().oldest_upload ? `${bytes(bl().upload_bytes)} · oldest ${duration(now() - bl().oldest_upload!)}; given up after a day` : "none in progress"}
          tone={old(bl().oldest_upload) ? "warn" : ""}
        />
      </div>

      <Panel title="Maintenance per node" note="totals since each node started">
        <Table
          count={props.cluster.nodes.length}
          columns={[
            "Node",
            "Last pass",
            { label: "Passes", num: true },
            "File sweep at",
            { label: "GC: pending / files / dirs", num: true },
            { label: "Packing jobs", num: true },
            { label: "Blobs packed", num: true },
            { label: "Bytes moved", num: true },
          ]}
        >
          <For each={props.cluster.nodes}>
            {(n) => {
              const st = () => statsOf(n);
              return (
                <tr>
                  <td>
                    <LiveDot live={n.live} />#{n.id}
                  </td>
                  <Show
                    when={st()}
                    fallback={
                      <td colspan={7} class="subtle">
                        {!n.live ? "down" : (statsError(n) ?? "no data")}
                      </td>
                    }
                  >
                    {(st) => {
                      const m = () => st().maintenance;
                      const next = () => (m().last_started ?? st().started_at) + m().interval_secs;
                      return (
                        <>
                          <td>
                            <Show
                              when={!m().running_since}
                              fallback={
                                <>
                                  <Badge tone="accent">running</Badge> for {duration(st().now - m().running_since!)}
                                </>
                              }
                            >
                              {m().last_started ? ago(m().last_started) : "not yet"}
                              <div class="subtle small">
                                {m().last_started ? `took ${duration(m().last_duration)} · ` : ""}
                                {(m().last_started ? "next" : "first") + " in " + duration(next() - st().now)}
                              </div>
                            </Show>
                          </td>
                          <td class="num">{num(m().passes)}</td>
                          <td class="mono small">
                            <Show when={m().last_started} fallback="–">
                              {hex(m().sweep_shard)} <span class="subtle">of {hex(m().shards)}</span>
                            </Show>
                          </td>
                          <td class="num">
                            {num(m().gc.pending)} / {num(m().gc.files)} / {num(m().gc.dirs)}
                            <Show when={m().gc.errors}>
                              <div>
                                <Badge tone="bad">{num(m().gc.errors)} errors</Badge>
                              </div>
                            </Show>
                          </td>
                          <td class="num">
                            {num(m().packer.jobs)}
                            <Show when={m().packer.failed}>
                              <div>
                                <Badge tone="bad">{num(m().packer.failed)} failed</Badge>
                              </div>
                            </Show>
                          </td>
                          <td class="num">
                            {num(m().packer.blobs)} → {num(m().packer.parts)} parts
                          </td>
                          <td class="num">{bytes(m().packer.bytes)}</td>
                        </>
                      );
                    }}
                  </Show>
                </tr>
              );
            }}
          </For>
        </Table>
      </Panel>

      <LifecyclePanel />

      <Panel title="Recent events" note="what passes did, and what failed; the last 100 per node">
        <div class="events">
          <Table count={events().length} empty="Nothing happened yet: passes that do nothing aren't listed." columns={["When", "Node", "Source", "Message"]}>
            <For each={events()}>
              {(e) => (
                <tr class={e.error ? "error" : ""}>
                  <td class="subtle" title={date(e.time)}>
                    {ago(e.time)}
                  </td>
                  <td>#{e.node}</td>
                  <td>
                    <Badge tone={e.error ? "bad" : ""}>{e.source}</Badge>
                  </td>
                  <td class="msg">{e.message}</td>
                </tr>
              )}
            </For>
          </Table>
        </div>
      </Panel>
    </>
  );
}

const DAY = 86400;

/** Lifecycle sweeps: the cluster's rate, whether a round of every bucket's
 * sweep fits in a day at it, and each bucket's sweep. */
function LifecyclePanel() {
  const lifecycle = poll(api.lifecycle, 10000);
  return (
    <Show when={lifecycle.data()} fallback={<Loading error={lifecycle.error()} />}>
      {(l) => <LifecycleView lifecycle={l()} refresh={lifecycle.refresh} />}
    </Show>
  );
}

function LifecycleView(props: { lifecycle: Lifecycle; refresh: () => void }) {
  const l = () => props.lifecycle;
  const [rate, setRate] = createSignal("");
  const late = () => (l().round_secs ?? 0) > DAY;
  // Steps that had more to do than their share fell short of the rate set:
  // one step at a time can't go faster (the database's latency, say).
  const short = () => l().rate > 0 && l().reached_rate != null && l().reached_rate! < 0.9 * l().rate;
  const submit = async (e: SubmitEvent) => {
    e.preventDefault();
    const value = Number(rate().replaceAll(/[ ,_]/g, ""));
    if (!Number.isInteger(value) || value < 0) {
      await act(() => Promise.reject(new Error("The rate is a whole number of versions per hour, 0 or more.")));
      return;
    }
    if (await act(() => api.setLifecycleRate(value), `Lifecycle rate set to ${num(value)} versions an hour`)) {
      setRate("");
      props.refresh();
    }
  };
  const round = () => {
    if (l().rate === 0) return "paused";
    return (l().round_partial ? "≥ " : "") + duration(l().round_secs);
  };
  return (
    <Panel
      title="Lifecycle sweeps"
      note="one step at a time across the cluster, about once a minute; each bucket with rules is swept once a day"
    >
      <div class="cards">
        <Card
          label="Rate"
          value={l().rate === 0 ? "paused" : `${num(l().rate)}/h`}
          note={
            <>
              versions read per hour, across the cluster (default {num(l().default_rate)})
              <Show when={l().reached_rate != null}>
                <div>
                  reached {num(Math.round(l().reached_rate!))}/h when busy, {ago(l().reached_at)}
                  {short() ? ": steps can't keep up with the rate set" : ""}
                </div>
              </Show>
            </>
          }
          tone={l().rate === 0 || short() ? "warn" : ""}
        />
        <Card
          label="A round takes"
          value={round()}
          note={
            `${num(l().round_versions)} versions in ${num(l().buckets.length)} buckets, at ` +
            (l().reached_rate != null && l().reached_rate! < l().rate ? "the rate reached" : "the rate set") +
            (late()
              ? `: over a day, so expirations run up to ${duration((l().round_secs ?? 0) - DAY)} late. ` +
                (short()
                  ? "Steps don't reach the rate set: the database's load or latency is the limit."
                  : "Raise the rate.")
              : "")
          }
          tone={late() || l().rate === 0 ? "warn" : ""}
        />
        <Card
          label="Last step"
          value={l().stepping ? "running" : ago(l().last_step)}
          note={l().last_step ? `began ${date(l().last_step)}` : "none yet"}
          tone={l().stepping ? "accent" : ""}
        />
      </div>
      <form class="form-row" onSubmit={submit}>
        <input
          type="text"
          inputmode="numeric"
          placeholder={`${num(l().rate)} versions an hour`}
          aria-label="Lifecycle rate"
          value={rate()}
          onInput={(e) => setRate(e.currentTarget.value)}
        />
        <button class="primary" type="submit">
          Set rate
        </button>
      </form>
      <Table
        count={l().buckets.length}
        empty="No bucket has lifecycle rules."
        columns={[
          "Bucket",
          { label: "Rules", num: true },
          "Sweep",
          "Last sweep",
          { label: "Expired / removed / aborted", num: true },
        ]}
      >
        <For each={l().buckets}>{(b) => <LifecycleRow bucket={b} />}</For>
      </Table>
    </Panel>
  );
}

function LifecycleRow(props: { bucket: LifecycleBucket }) {
  const b = () => props.bucket;
  const due = () => b().due != null && b().due! <= now();
  return (
    <tr>
      <td>
        <A href={`/buckets/${encodeURIComponent(b().bucket)}/lifecycle`}>{b().bucket}</A>
      </td>
      <td class="num">
        {num(b().enabled)}
        <Show when={b().enabled !== b().rules}>
          <span class="subtle"> of {num(b().rules)}</span>
        </Show>
      </td>
      <td>
        <Show
          when={b().sweep}
          fallback={<span class="subtle">{due() ? "due, waiting for its turn" : `next in ${duration((b().due ?? now()) - now())}`}</span>}
        >
          {(s) => (
            <>
              <Badge tone="accent">in progress</Badge> {num(s().read)} read
              <Show when={b().last?.read}>{(total) => <> ({pct(s().read, total())})</>}</Show>
              <div class="subtle small">
                started {ago(s().started)} · at <span class="mono">{s().key || "the start"}</span>
              </div>
            </>
          )}
        </Show>
      </td>
      <td>
        <Show when={b().last} fallback={<span class="subtle">none yet</span>}>
          {(last) => (
            <>
              took {duration(last().finished - last().started)}
              <Show when={last().finished - last().started > DAY}>
                {" "}
                <Badge tone="warn">over a day</Badge>
              </Show>
              <div class="subtle small">
                {num(last().read)} read · ended {ago(last().finished)}
              </div>
            </>
          )}
        </Show>
      </td>
      <td class="num">
        <Show when={b().last} fallback="–">
          {(last) => (
            <>
              {num(last().expired)} / {num(last().removed)} / {num(last().aborted)}
            </>
          )}
        </Show>
      </td>
    </tr>
  );
}
