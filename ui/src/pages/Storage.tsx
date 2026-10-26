import { For, Show, createMemo } from "solid-js";
import { type Cluster, type Storage as StorageInfo, api, diskOf } from "../api";
import { Badge, Bar, Card, LiveDot, Loading, Panel, Table, poll } from "../components/ui";
import { bytes, num, pct } from "../format";

export default function Storage() {
  // The catalog's numbers take a scan, so they're refreshed less often.
  const data = poll(() => Promise.all([api.storage(), api.cluster()]), 30000);
  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      {(d) => <View storage={d()[0]} cluster={d()[1]} />}
    </Show>
  );
}

function View(props: { storage: StorageInfo; cluster: Cluster }) {
  const s = () => props.storage;
  const rf = () => s().replication_factor;
  const health = createMemo(() => {
    const h = { healthy: 0, healthyBytes: 0, under: 0, underBytes: 0, lost: 0, lostBytes: 0 };
    for (const g of s().replicas) {
      if (g.live === 0) {
        h.lost += g.blobs;
        h.lostBytes += g.bytes;
      } else if (g.live < rf()) {
        h.under += g.blobs;
        h.underBytes += g.bytes;
      } else {
        h.healthy += g.blobs;
        h.healthyBytes += g.bytes;
      }
    }
    return h;
  });
  const held = (node: number) => s().nodes.find((n) => n.node === node) ?? { blobs: 0, bytes: 0 };
  const o = () => s().objects;
  const b = () => s().blobs;

  return (
    <>
      <div class="page-head">
        <h1>Storage</h1>
        <span class="subtle small">Counted from the catalog; refreshes every 30 s</span>
      </div>
      <div class="cards">
        <Card label="Objects" value={num(o().current)} note={`${bytes(o().current_bytes)} in ${num(o().buckets)} buckets`} />
        <Card
          label="Older versions"
          value={num(o().noncurrent)}
          note={`${bytes(o().noncurrent_bytes)} · ${num(o().delete_markers)} delete markers`}
        />
        <Card label="Blobs" value={num(b().committed)} note={`${bytes(b().bytes)} before replication`} />
        <Card
          label="Garbage"
          value={bytes(b().garbage_bytes)}
          note={`${pct(b().garbage_bytes, b().bytes)} of blob bytes, freed by compaction`}
          tone={b().garbage_bytes / Math.max(1, b().bytes) > 0.3 ? "warn" : ""}
        />
        <Card
          label="Fully replicated"
          value={pct(health().healthyBytes, health().healthyBytes + health().underBytes + health().lostBytes)}
          note={`${num(health().healthy)} blobs with ≥ ${rf()} live copies`}
          tone={health().under + health().lost ? "warn" : "ok"}
        />
        <Card
          label="Under-replicated"
          value={num(health().under)}
          note={`${bytes(health().underBytes)} with fewer live copies than ${rf()}`}
          tone={health().under ? "warn" : "ok"}
        />
        <Card
          label="Unavailable"
          value={num(health().lost)}
          note={`${bytes(health().lostBytes)} with no live copy`}
          tone={health().lost ? "bad" : "ok"}
        />
      </div>

      <div class="grid cols-2">
        <Panel title="Replicas" note={`committed blobs by copies on live nodes · replication factor ${rf()}`}>
          <Table
            count={s().replicas.length}
            empty="No blobs yet."
            columns={[{ label: "Live copies", num: true }, { label: "Copies", num: true }, "", { label: "Blobs", num: true }, { label: "Bytes", num: true }, ""]}
          >
            <For each={s().replicas}>
              {(g) => (
                <tr>
                  <td class="num">{num(g.live)}</td>
                  <td class="num">{num(g.copies)}</td>
                  <td>
                    <Badge tone={g.live === 0 ? "bad" : g.live < rf() ? "warn" : "ok"}>
                      {g.live === 0 ? "unavailable" : g.live < rf() ? "under-replicated" : g.live > rf() ? "over-replicated" : "healthy"}
                    </Badge>
                    <Show when={g.copies > g.live}>
                      <div class="subtle small">{g.copies - g.live} on down nodes</div>
                    </Show>
                  </td>
                  <td class="num">{num(g.blobs)}</td>
                  <td class="num">{bytes(g.bytes)}</td>
                  <td class="share">
                    <Bar used={g.bytes} total={b().bytes} warnAt={2} badAt={2} />
                  </td>
                </tr>
              )}
            </For>
          </Table>
        </Panel>
        <Panel title="Data per node" note="committed blobs each node holds a copy of">
          <Table
            count={props.cluster.nodes.length}
            columns={["Node", "Peer URL", { label: "Blobs", num: true }, { label: "Bytes", num: true }, { label: "Share", num: true }, "Disk"]}
          >
            <For each={props.cluster.nodes}>
              {(n) => {
                const d = () => diskOf(n);
                return (
                  <tr>
                    <td>
                      <LiveDot live={n.live} />#{n.id}
                    </td>
                    <td class="mono">{n.peer_url}</td>
                    <td class="num">{num(held(n.id).blobs)}</td>
                    <td class="num">{bytes(held(n.id).bytes)}</td>
                    <td class="num">{pct(held(n.id).bytes, b().bytes * rf())}</td>
                    <td class="disk">
                      <Show when={d()} fallback={<span class="subtle small">{bytes(n.free_space)} free (as of last heartbeat)</span>}>
                        <Bar used={d()!.total - d()!.available} total={d()!.total} />
                        <div class="bar-label">
                          <span>{pct(d()!.total - d()!.available, d()!.total)} used</span>
                          <span>{bytes(d()!.available)} free</span>
                        </div>
                      </Show>
                    </td>
                  </tr>
                );
              }}
            </For>
          </Table>
        </Panel>
      </div>
    </>
  );
}
