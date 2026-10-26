import { For, Show, createMemo, createSignal } from "solid-js";
import { type Cluster, api, diskOf, statsOf } from "../api";
import { LineChart } from "../components/LineChart";
import { Badge, Bar, Card, LiveDot, Loading, Panel, Table, poll } from "../components/ui";
import { ago, bytes, duration, num, pct, rate } from "../format";
import { mergeHistory, opsTotals, recentRates, series } from "../metrics";

const SPANS: [number, string][] = [
  [300, "5 min"],
  [900, "15 min"],
  [1800, "30 min"],
  [3600, "1 hour"],
];

export default function Overview() {
  const cluster = poll(api.cluster, 5000);
  return (
    <Show when={cluster.data()} fallback={<Loading error={cluster.error()} />}>
      {(c) => <View cluster={c()} />}
    </Show>
  );
}

function View(props: { cluster: Cluster }) {
  const [span, setSpan] = createSignal(900);
  const nodes = () => props.cluster.nodes;
  const live = () => nodes().filter((n) => n.live);
  const rf = () => props.cluster.replication_factor;
  const history = createMemo(() => mergeHistory(nodes()));
  const r = createMemo(() => recentRates(history()));
  const rfs = () => [...new Set(live().flatMap((n) => statsOf(n)?.replication_factor ?? []))];
  const disk = createMemo(() => {
    let total = 0;
    let available = 0;
    for (const n of live()) {
      const d = diskOf(n);
      if (d) {
        total += d.total;
        available += d.available;
      }
    }
    return { total, available };
  });
  const inFlight = () => live().reduce((a, n) => a + (statsOf(n)?.in_flight ?? 0), 0);
  const perSec = (k: "requests" | "client_errors" | "server_errors" | "bytes_in" | "bytes_out") => (c: Record<typeof k, number>) =>
    c[k] / history().slotSecs;
  const ops = () => opsTotals(live()).filter((o) => o.requests).sort((a, b) => b.requests - a.requests);

  return (
    <>
      <div class="page-head">
        <h1>Overview</h1>
        <div class="form-row">
          <span class="subtle">Charts show</span>
          <select value={span()} onChange={(e) => setSpan(Number(e.currentTarget.value))}>
            <For each={SPANS}>{([v, label]) => <option value={v}>{label}</option>}</For>
          </select>
        </div>
      </div>

      <div class="cards">
        <Card
          label="Nodes live"
          value={`${live().length} / ${nodes().length}`}
          note={
            live().length < rf()
              ? `fewer than the replication factor (${rf()}): uploads fail`
              : live().length < nodes().length
                ? "some nodes are down"
                : "all nodes are up"
          }
          tone={live().length < rf() ? "bad" : live().length < nodes().length ? "warn" : "ok"}
        />
        <Card
          label="Replication factor"
          value={rfs().length > 1 ? rfs().join(" / ") : String(rf())}
          note={rfs().length > 1 ? "nodes disagree: check --replication-factor" : "copies of every blob"}
          tone={rfs().length > 1 ? "bad" : ""}
        />
        <Card label="Requests" value={rate(r().requests) + "/s"} note={`${num(inFlight())} in flight · last minute`} />
        <Card
          label="Errors"
          value={rate(r().server_errors + r().client_errors) + "/s"}
          note={`${rate(r().server_errors)}/s server · ${rate(r().client_errors)}/s client`}
          tone={r().requests && r().server_errors / r().requests > 0.01 ? "bad" : r().server_errors ? "warn" : ""}
        />
        <Card
          label="Throughput"
          value={bytes(r().bytes_in + r().bytes_out) + "/s"}
          note={`${bytes(r().bytes_in)}/s in · ${bytes(r().bytes_out)}/s out`}
        />
        <Card label="Latency" value={duration(r().latency)} note="average, to response headers" />
        <Card
          label="Disk"
          value={disk().total ? pct(disk().total - disk().available, disk().total) + " used" : "–"}
          note={disk().total ? `${bytes(disk().available)} free of ${bytes(disk().total)}, over live nodes` : ""}
          tone={!disk().total ? "" : disk().available / disk().total < 0.08 ? "bad" : disk().available / disk().total < 0.2 ? "warn" : ""}
        />
      </div>

      <div class="grid cols-3">
        <Panel title="Requests" note="per second">
          <LineChart
            format={rate}
            series={[
              { name: "all", color: 1, fill: true, points: series(history(), span(), perSec("requests")) },
              { name: "4xx", color: 2, points: series(history(), span(), perSec("client_errors")) },
              { name: "5xx", color: 3, points: series(history(), span(), perSec("server_errors")) },
            ]}
          />
        </Panel>
        <Panel title="Throughput" note="per second">
          <LineChart
            format={bytes}
            series={[
              { name: "in", color: 1, fill: true, points: series(history(), span(), perSec("bytes_in")) },
              { name: "out", color: 4, fill: true, points: series(history(), span(), perSec("bytes_out")) },
            ]}
          />
        </Panel>
        <Panel title="Latency" note="average, to response headers">
          <LineChart
            format={duration}
            series={[
              {
                name: "latency",
                color: 2,
                points: series(history(), span(), (c) => (c.requests ? c.latency_us / c.requests / 1e6 : 0)),
              },
            ]}
          />
        </Panel>
      </div>

      <div class="stack">
        <Panel title="Nodes" note="a node is live if it was seen in the last 10 s">
          <Table
            count={nodes().length}
            columns={["Node", "Peer URL", "Status", "Version", "Disk", { label: "Requests", num: true }, { label: "In flight", num: true }, "Last maintenance"]}
          >
            <For each={nodes()}>
              {(n) => {
                const st = () => statsOf(n);
                const d = () => diskOf(n);
                const m = () => st()?.maintenance;
                return (
                  <tr>
                    <td>
                      <LiveDot live={n.live} />#{n.id}{" "}
                      <Show when={n.id === props.cluster.this_node}>
                        <Badge tone="accent">this node</Badge>
                      </Show>
                    </td>
                    <td class="mono">
                      {n.peer_url}
                      <div class="subtle small">{n.node_id}</div>
                    </td>
                    <td>
                      <Show when={n.live} fallback={<Badge tone="bad">down</Badge>}>
                        <Show when={st()} fallback={<Badge tone="warn">not answering</Badge>}>
                          <Badge tone="ok">live</Badge>
                        </Show>
                      </Show>
                      <div class="subtle small">
                        {!n.live
                          ? "last seen " + ago(n.last_seen)
                          : st()
                            ? "up " + duration(st()!.now - st()!.started_at)
                            : n.stats && "error" in n.stats
                              ? n.stats.error
                              : ""}
                      </div>
                    </td>
                    <td>
                      {st()?.version ?? "–"}
                      <Show when={st() && st()!.replication_factor !== props.cluster.replication_factor}>
                        <div>
                          <Badge tone="bad">RF {st()!.replication_factor}</Badge>
                        </div>
                      </Show>
                    </td>
                    <td class="disk">
                      <Show when={d()} fallback={<span class="subtle small">{bytes(n.free_space)} free</span>}>
                        <Bar used={d()!.total - d()!.available} total={d()!.total} />
                        <div class="bar-label">
                          <span>{pct(d()!.total - d()!.available, d()!.total)} used</span>
                          <span>
                            {bytes(d()!.available)} free of {bytes(d()!.total)}
                          </span>
                        </div>
                      </Show>
                    </td>
                    <td class="num">{st() ? rate(recentRates(mergeHistory([n])).requests) + "/s" : "–"}</td>
                    <td class="num">{st() ? num(st()!.in_flight) : "–"}</td>
                    <td>
                      <Show when={m()} fallback="–">
                        <Show when={!m()!.running_since} fallback={<Badge tone="accent">running</Badge>}>
                          {m()!.last_started ? ago(m()!.last_started) : "not yet"}
                        </Show>
                      </Show>
                    </td>
                  </tr>
                );
              }}
            </For>
          </Table>
        </Panel>

        <Panel title="Requests by operation" note="since each node started">
          <Table
            count={ops().length}
            empty="No requests yet."
            columns={[
              "Operation",
              { label: "Requests", num: true },
              { label: "4xx", num: true },
              { label: "5xx", num: true },
              { label: "Avg latency", num: true },
              { label: "In", num: true },
              { label: "Out", num: true },
            ]}
          >
            <For each={ops()}>
              {(o) => (
                <tr>
                  <td>{o.op}</td>
                  <td class="num">{num(o.requests)}</td>
                  <td class="num">{num(o.client_errors)}</td>
                  <td class="num">
                    <Show when={o.server_errors} fallback="0">
                      <Badge tone="bad">{num(o.server_errors)}</Badge>
                    </Show>
                  </td>
                  <td class="num">{duration(o.latency_us / o.requests / 1e6)}</td>
                  <td class="num">{bytes(o.bytes_in)}</td>
                  <td class="num">{bytes(o.bytes_out)}</td>
                </tr>
              )}
            </For>
          </Table>
        </Panel>
      </div>
    </>
  );
}
