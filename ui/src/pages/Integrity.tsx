import { A } from "@solidjs/router";
import { For, Show, createMemo } from "solid-js";
import { type Cluster, type Integrity as IntegrityInfo, type Storage, api, statsOf } from "../api";
import { Badge, Card, LiveDot, Loading, Panel, type Tone, Table, poll } from "../components/ui";
import { ago, bytes, date, duration, num, pct, plural } from "../format";
import { objectUrl } from "./Buckets";

/** The least time between two checks of a copy (`scrub::MIN_INTERVAL`). */
const MIN_PERIOD = 7 * 86400;
/** A node whose period is longer than this is warned about. */
const WARN_PERIOD = 30 * 86400;
/** This many findings on a node in a day suggest a failing disk. */
const MANY_FINDINGS = 10;

export default function Integrity() {
  const data = poll(() => Promise.all([api.integrity(), api.storage(), api.cluster()]), 30000);
  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      {(d) => <View integrity={d()[0]} storage={d()[1]} cluster={d()[2]} />}
    </Show>
  );
}

function View(props: { integrity: IntegrityInfo; storage: Storage; cluster: Cluster }) {
  const i = () => props.integrity;
  const coverage = () => props.storage.integrity;
  const covered = (node: number) => coverage().nodes.find((n) => n.node === node);
  const recent = (node: number) => i().recent.find((n) => n.node === node)?.findings ?? 0;
  /** How long a node takes to check all it holds, at its rate. */
  const period = (node: number): number | null => {
    const rate = statsOf(props.cluster.nodes.find((n) => n.id === node)!)?.scrub_rate;
    const held = covered(node)?.bytes ?? 0;
    if (!rate) return null;
    return Math.max(MIN_PERIOD, held / rate);
  };
  const totals = createMemo(() => {
    const t = { bytes: 0, unchecked: 0 };
    for (const n of coverage().nodes) {
      t.bytes += n.bytes;
      t.unchecked += n.unchecked_bytes;
    }
    return t;
  });
  const longest = createMemo(() => {
    let longest = 0;
    for (const n of props.cluster.nodes) if (n.live) longest = Math.max(longest, period(n.id) ?? Infinity);
    return longest;
  });

  return (
    <>
      <div class="page-head">
        <h1>Integrity</h1>
        <span class="subtle small">What the scrubbers checked and found; refreshes every 30 s</span>
      </div>
      <div class="cards">
        <Card
          label="Objects with lost data"
          value={num(i().lost_objects)}
          note={i().lost_objects ? "intact on no replica: reads of it fail" : "every byte is intact somewhere"}
          tone={i().lost_objects ? "bad" : "ok"}
        />
        <Card
          label="Open findings"
          value={num(i().open_findings)}
          note="damaged or missing copies not repaired yet"
          tone={i().open_findings ? "warn" : "ok"}
        />
        <Card
          label="Checked"
          value={pct(totals().bytes - totals().unchecked, totals().bytes)}
          note={`of ${bytes(totals().bytes)} in copies; ${bytes(totals().unchecked)} not checked yet`}
          tone={totals().unchecked ? "" : "ok"}
        />
        <Card
          label="Full check every"
          value={isFinite(longest()) ? duration(longest()) : "never"}
          note={isFinite(longest()) ? "on the slowest live node, at its rate" : "scrubbing is off on a live node"}
          tone={longest() > WARN_PERIOD ? "warn" : ""}
        />
        <Show when={coverage().legacy_blobs}>
          <Card
            label="From before checksums"
            value={bytes(coverage().legacy_bytes)}
            note={`${num(coverage().legacy_blobs)} blobs that can't be checked`}
            tone="warn"
          />
        </Show>
      </div>

      <Panel title="Scrubbing per node" note="each node checks the copies it holds">
        <Table
          count={props.cluster.nodes.length}
          columns={[
            "Node",
            { label: "Rate", num: true },
            { label: "Holds", num: true },
            { label: "Full check every", num: true },
            "Least recently checked",
            { label: "Checked since start", num: true },
            "Found since start",
            { label: "Findings (24 h)", num: true },
          ]}
        >
          <For each={props.cluster.nodes}>
            {(n) => {
              const c = () => covered(n.id);
              const s = () => statsOf(n);
              const p = () => period(n.id);
              const findings = () => recent(n.id);
              return (
                <tr>
                  <td>
                    <LiveDot live={n.live} />#{n.id}
                  </td>
                  <td class="num">
                    <Show when={s()} fallback="–">
                      {s()!.scrub_rate ? bytes(s()!.scrub_rate) + "/s" : <Badge tone="warn">off</Badge>}
                    </Show>
                  </td>
                  <td class="num">{bytes(c()?.bytes ?? 0)}</td>
                  <td class="num">
                    <Show when={p() != null} fallback="–">
                      <span class={p()! > WARN_PERIOD ? "warn-text" : ""} title={p()! > WARN_PERIOD ? "the rate is too low for what the node holds" : ""}>
                        {duration(p())}
                      </span>
                    </Show>
                  </td>
                  <td>
                    <Show when={c()?.unchecked} fallback={c()?.oldest_checked ? ago(c()!.oldest_checked) : "–"}>
                      {plural(c()!.unchecked, "copy", "copies")} ({bytes(c()!.unchecked_bytes)}) not yet
                    </Show>
                  </td>
                  <td class="num">
                    <Show when={s()} fallback="–">
                      {num(s()!.maintenance.scrub.copies)} · {bytes(s()!.maintenance.scrub.bytes)}
                    </Show>
                  </td>
                  <td>
                    <Show when={s()} fallback="–">
                      <Show when={s()!.maintenance.scrub.damaged} fallback={<span class="subtle">nothing</span>}>
                        {num(s()!.maintenance.scrub.damaged)} damaged · {num(s()!.maintenance.scrub.repaired)} repaired
                        <Show when={s()!.maintenance.scrub.lost}> · {num(s()!.maintenance.scrub.lost)} lost</Show>
                      </Show>
                    </Show>
                  </td>
                  <td class="num">
                    <Show when={findings()} fallback="0">
                      <Badge tone={findings() >= MANY_FINDINGS ? "bad" : "warn"}>{num(findings())}</Badge>
                      <Show when={findings() >= MANY_FINDINGS}>
                        <div class="subtle small">failing disk?</div>
                      </Show>
                    </Show>
                  </td>
                </tr>
              );
            }}
          </For>
        </Table>
      </Panel>

      <Panel
        title="Objects with lost data"
        note={i().lost_objects > i().lost.length ? `the ${num(i().lost.length)} most recent of ${num(i().lost_objects)}` : "bytes intact on no replica"}
      >
        <Table
          count={i().lost.length}
          empty="None: every byte is intact on some replica."
          columns={["Object", "Version", { label: "Size", num: true }, { label: "Lost", num: true }, "Since"]}
        >
          <For each={i().lost}>
            {(o) => (
              <tr>
                <td class="key">
                  <span class="subtle">{o.bucket}/</span>
                  <A href={objectUrl(o.bucket, o.key)}>{o.key}</A>
                </td>
                <td>
                  <Show
                    when={o.version_id}
                    fallback={
                      <>
                        <Badge>upload</Badge> <span class="mono small subtle">{o.upload_id}</span>
                      </>
                    }
                  >
                    {o.latest ? <Badge tone="accent">current</Badge> : <Badge>older</Badge>}{" "}
                    <span class="mono small subtle">{o.version_id}</span>
                  </Show>
                </td>
                <td class="num">{bytes(o.size)}</td>
                <td class="num">
                  <Badge tone="bad">{bytes(o.lost_bytes)}</Badge>
                </td>
                <td>{date(o.since)}</td>
              </tr>
            )}
          </For>
        </Table>
      </Panel>

      <Panel title="Findings" note="open ones first, then those resolved in the last 30 days">
        <Table
          count={i().findings.length}
          empty="Nothing found: every copy checked so far was intact."
          columns={["Found", "Node", "Blob", "Problem", "Detail", "Outcome"]}
        >
          <For each={i().findings}>
            {(f) => (
              <tr>
                <td>{date(f.found_at)}</td>
                <td>#{f.node}</td>
                <td class="mono small">{f.blob_id}</td>
                <td>
                  <Badge tone={problemTone(f.problem)}>{f.problem}</Badge>
                  <Show when={f.bad_blocks}>
                    <div class="subtle small">{plural(f.bad_blocks, "block")}</div>
                  </Show>
                </td>
                <td class="small">{f.detail}</td>
                <td>
                  <Show when={f.outcome} fallback={<Badge tone="warn">open</Badge>}>
                    <Badge tone={outcomeTone(f.outcome!)}>{f.outcome}</Badge>
                  </Show>
                  <Show when={f.resolved_at}>
                    <div class="subtle small">{date(f.resolved_at)}</div>
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </Table>
      </Panel>
    </>
  );
}

function problemTone(problem: string): Tone {
  return problem === "catalog" ? "bad" : "warn";
}

function outcomeTone(outcome: string): Tone {
  return outcome === "repaired" ? "ok" : outcome === "lost" ? "bad" : "";
}
