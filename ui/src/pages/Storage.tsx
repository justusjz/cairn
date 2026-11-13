import { For, Show, createMemo, createSignal } from "solid-js";
import { type Cluster, type Storage as StorageInfo, api, diskOf } from "../api";

type ReplicaGroup = StorageInfo["replicas"][number];
import { Badge, Bar, Card, LiveDot, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { bytes, num, pct, plural } from "../format";
import { KmsPanel } from "./Users";

export default function Storage() {
  // The catalog's numbers take a scan, so they're refreshed less often.
  const data = poll(() => Promise.all([api.storage(), api.cluster()]), 30000);
  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      {(d) => <View storage={d()[0]} cluster={d()[1]} refresh={data.refresh} />}
    </Show>
  );
}

function View(props: { storage: StorageInfo; cluster: Cluster; refresh: () => void }) {
  const s = () => props.storage;
  const rf = () => s().replication_factor;
  // A blob is readable with as many live shards as it has data shards (one
  // for a replicated blob), and as redundant as the replication factor asks
  // with that many more than one.
  const wanted = (g: ReplicaGroup) => g.data_shards + rf() - 1;
  const health = createMemo(() => {
    const h = { healthy: 0, healthyBytes: 0, under: 0, underBytes: 0, lost: 0, lostBytes: 0 };
    for (const g of s().replicas) {
      if (g.live < g.data_shards) {
        h.lost += g.blobs;
        h.lostBytes += g.bytes;
      } else if (g.live < wanted(g)) {
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
          label="Fully redundant"
          value={pct(health().healthyBytes, health().healthyBytes + health().underBytes + health().lostBytes)}
          note={`${num(health().healthy)} blobs that survive losing ${rf() - 1} more nodes`}
          tone={health().under + health().lost ? "warn" : "ok"}
        />
        <Card
          label="Under-replicated"
          value={num(health().under)}
          note={`${bytes(health().underBytes)} with fewer live shards than that takes`}
          tone={health().under ? "warn" : "ok"}
        />
        <Card
          label="Unavailable"
          value={num(health().lost)}
          note={`${bytes(health().lostBytes)} with too few live shards to read`}
          tone={health().lost ? "bad" : "ok"}
        />
      </div>

      <Redundancy storage={s()} cluster={props.cluster} refresh={props.refresh} />

      <div class="grid cols-2">
        <Panel
          title="Shards"
          note={`committed blobs by layout and shards on live nodes · replication factor ${rf()}`}
        >
          <Table
            count={s().replicas.length}
            empty="No blobs yet."
            columns={["Layout", { label: "Live shards", num: true }, { label: "Shards", num: true }, "", { label: "Blobs", num: true }, { label: "Bytes", num: true }, ""]}
          >
            <For each={s().replicas}>
              {(g) => (
                <tr>
                  <td>
                    {g.data_shards === 1 ? "replicated" : `coded ${g.data_shards}+${g.copies - g.data_shards}`}
                  </td>
                  <td class="num">{num(g.live)}</td>
                  <td class="num">{num(g.copies)}</td>
                  <td>
                    <Badge tone={g.live < g.data_shards ? "bad" : g.live < wanted(g) ? "warn" : "ok"}>
                      {g.live < g.data_shards
                        ? "unavailable"
                        : g.live < wanted(g)
                          ? "under-replicated"
                          : g.live > wanted(g)
                            ? "over-replicated"
                            : "healthy"}
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
        <Panel title="Data per node" note="committed blobs each node holds a shard of">
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
      <KmsPanel cluster={props.cluster} refresh={props.refresh} />
    </>
  );
}

/** The cluster's redundancy settings: how many nodes every blob survives
 * losing (parity shards), what large blobs are coded into (data shards), and
 * when a node that's down has its shards rebuilt. */
function Redundancy(props: { storage: StorageInfo; cluster: Cluster; refresh: () => void }) {
  const pk = () => props.storage.packer;
  const after = () => props.storage.backlog.repair_after;
  const active = () => props.cluster.nodes.filter((n) => n.state === "active").length;
  const set = async (name: string, value: number | null, done: string) => {
    const result = await act(() => api.setSetting(name, value), done);
    if (result) {
      for (const warning of result.value.warnings) toast(warning, true);
      props.refresh();
    }
  };
  return (
    <Panel
      title="Redundancy"
      note={`for the whole cluster · new blobs follow a change within a heartbeat, existing ones are rewritten in the background (Jobs) · ${num(active())} active nodes`}
    >
      <Table count={3} columns={["Setting", "Now", "", "Change"]}>
        <SettingRow
          label="Parity shards"
          value={`${num(pk().parity_shards)}`}
          note={
            pk().parity_setting == null
              ? `from each node's --replication-factor (${num(pk().parity_shards + 1)} copies on this one), for new blobs only; set it here for the whole cluster`
              : `every blob survives losing ${plural(pk().parity_shards, "node", "nodes")}` +
                (pk().data_shards > 1
                  ? `: blobs over ${bytes(pk().small_size)} are coded ${pk().data_shards}+${pk().parity_shards}, smaller ones get ${plural(pk().parity_shards + 1, "copy", "copies")} until they're packed`
                  : `: ${plural(pk().parity_shards + 1, "copy", "copies")} of each`)
          }
          placeholder="parity shards"
          min={0}
          max={pk().max_parity_shards}
          onSet={(v) => set("parity-shards", v, `Parity shards set to ${num(v)}: every blob survives losing ${plural(v, "node", "nodes")}`)}
          unset={
            pk().parity_setting == null
              ? undefined
              : { label: "Use the nodes' flags", run: () => set("parity-shards", null, "Every node goes by its --replication-factor again") }
          }
        />
        <SettingRow
          label="Data shards"
          value={pk().data_shards > 1 ? `coded ${pk().data_shards}+${pk().parity_shards}` : "off"}
          note={
            pk().data_shards > 1
              ? `blobs over ${bytes(pk().small_size)} are erasure-coded into ${num(pk().data_shards)} data shards` +
                (pk().coding ? "" : `, once ${num(pk().data_shards + pk().parity_shards)} nodes are live; until then they're replicated`)
              : `1 keeps every blob replicated; more erasure-codes blobs over ${bytes(pk().small_size)}, which takes as many nodes as data and parity shards`
          }
          placeholder="data shards"
          min={1}
          max={pk().max_data_shards}
          onSet={(v) =>
            set("data-shards", v, v > 1 ? `Large blobs are coded ${num(v)}+${num(pk().parity_shards)} from now on` : "Erasure coding is off")
          }
        />
        <SettingRow
          label="Repair after"
          value={after() > 0 ? `${num(after())} min` : "off"}
          note={
            after() > 0
              ? "a node down that long has its shards rebuilt on the others, without being removed"
              : "a node that's down keeps its shards until it's removed (Overview: Remove)"
          }
          placeholder="minutes, 0 for off"
          min={0}
          onSet={(v) =>
            set("repair-after", v, v > 0 ? `Nodes down for ${num(v)} min have their shards rebuilt` : "Repair of nodes that are down is off")
          }
        />
      </Table>
    </Panel>
  );
}

/** A setting's row: its value, what it means, and a form to change it. */
function SettingRow(props: {
  label: string;
  value: string;
  note: string;
  placeholder: string;
  min: number;
  max?: number;
  onSet: (value: number) => void;
  unset?: { label: string; run: () => void };
}) {
  const [input, setInput] = createSignal("");
  const submit = (e: SubmitEvent) => {
    e.preventDefault();
    const value = Number(input().trim());
    if (input().trim() === "" || !Number.isInteger(value) || value < props.min || (props.max != null && value > props.max)) {
      toast(`${props.label}: a whole number from ${props.min}${props.max != null ? ` to ${props.max}` : " up"}`, true);
      return;
    }
    props.onSet(value);
    setInput("");
  };
  return (
    <tr>
      <td>{props.label}</td>
      <td>
        <strong>{props.value}</strong>
      </td>
      <td class="subtle small">{props.note}</td>
      <td>
        <form class="form-row" onSubmit={submit}>
          <input
            type="text"
            inputmode="numeric"
            placeholder={props.placeholder}
            aria-label={props.label}
            value={input()}
            onInput={(e) => setInput(e.currentTarget.value)}
          />
          <button class="primary" type="submit">
            Set
          </button>
          <Show when={props.unset}>
            <button type="button" onClick={() => props.unset!.run()}>
              {props.unset!.label}
            </button>
          </Show>
        </form>
      </td>
    </tr>
  );
}
