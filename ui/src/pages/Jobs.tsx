import { For, Show, createMemo } from "solid-js";
import { type Cluster, type Event, type Storage, api, statsOf } from "../api";
import { Badge, Card, LiveDot, Loading, Panel, Table, poll } from "../components/ui";
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
  const old = (t: number | null) => t !== null && now() - t > 3600;

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
                        {!n.live ? "down" : n.stats && "error" in n.stats ? n.stats.error : "no data"}
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
