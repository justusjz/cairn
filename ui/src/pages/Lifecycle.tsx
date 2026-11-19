// A bucket's lifecycle rules, to read and edit: the rules S3's
// PutBucketLifecycleConfiguration sets, in the form Cairn stores them (see
// `src/lifecycle/rules.rs`). The server checks them as it checks S3's.

import { A, useParams } from "@solidjs/router";
import { For, Show, createEffect, createSignal, on } from "solid-js";
import { type LifecycleConfiguration, type LifecycleRule, api } from "../api";
import { Loading, Panel, act } from "../components/ui";
import { bucketUrl } from "./Buckets";

const DAY_MS = 86400000;

/** A rule as the form holds it: numbers as typed. */
type Draft = {
  id: string;
  enabled: boolean;
  prefix: string;
  greater: string;
  less: string;
  /** Tags the objects must have, with these values (as typed: S3 doesn't
   * trim them). */
  tags: { key: string; value: string }[];
  /** What happens to current versions. */
  current: "none" | "days" | "date" | "markers";
  currentDays: string;
  /** `YYYY-MM-DD`, UTC. */
  currentDate: string;
  noncurrent: boolean;
  noncurrentDays: string;
  keep: string;
  abort: boolean;
  abortDays: string;
  /** Transitions of current versions into lower storage classes. */
  transitions: TransitionDraft[];
  /** Transitions of noncurrent versions. */
  noncurrentTransitions: NoncurrentTransitionDraft[];
};

type TransitionDraft = { by: "days" | "date"; days: string; date: string; storageClass: string };
type NoncurrentTransitionDraft = { days: string; keep: string; storageClass: string };

const isoDate = (day: number) => new Date(day * DAY_MS).toISOString().slice(0, 10);

const text = (n: number | null | undefined) => (n == null ? "" : String(n));

function fromRule(r: LifecycleRule): Draft {
  const e = r.expiration;
  return {
    id: r.id ?? "",
    enabled: r.enabled,
    prefix: r.filter.prefix ?? "",
    greater: text(r.filter.size_greater_than),
    less: text(r.filter.size_less_than),
    tags: (r.filter.tags ?? []).map((t) => ({ ...t })),
    current: e?.expired_object_delete_marker ? "markers" : e?.date != null ? "date" : e?.days != null ? "days" : "none",
    currentDays: text(e?.days),
    currentDate: e?.date != null ? isoDate(e.date) : "",
    noncurrent: r.noncurrent_expiration != null,
    noncurrentDays: text(r.noncurrent_expiration?.days),
    keep: text(r.noncurrent_expiration?.newer_versions),
    abort: r.abort_upload_days != null,
    abortDays: text(r.abort_upload_days),
    transitions: (r.transitions ?? []).map((t) => ({
      by: t.date != null ? "date" : "days",
      days: text(t.days),
      date: t.date != null ? isoDate(t.date) : "",
      storageClass: t.storage_class,
    })),
    noncurrentTransitions: (r.noncurrent_transitions ?? []).map((t) => ({
      days: text(t.days),
      keep: text(t.newer_versions),
      storageClass: t.storage_class,
    })),
  };
}

const blank = (): Draft => ({
  id: "",
  enabled: true,
  prefix: "",
  greater: "",
  less: "",
  tags: [],
  current: "days",
  currentDays: "30",
  currentDate: "",
  noncurrent: false,
  noncurrentDays: "30",
  keep: "",
  abort: false,
  abortDays: "7",
  transitions: [],
  noncurrentTransitions: [],
});

/** The whole number typed in `field` of rule `n`, if any. */
function number(value: string, what: string, n: number): number | null {
  const v = value.trim().replaceAll(/[ ,_]/g, "");
  if (!v) return null;
  if (!/^\d+$/.test(v)) throw new Error(`Rule ${n}: ${what} must be a whole number.`);
  return Number(v);
}

function required(value: string, what: string, n: number): number {
  const v = number(value, what, n);
  if (v == null) throw new Error(`Rule ${n}: ${what} is missing.`);
  return v;
}

/** The day of a `YYYY-MM-DD` date typed in rule `n`. */
function day(value: string, what: string, n: number): number {
  const t = Date.parse(value + "T00:00:00Z");
  if (isNaN(t)) throw new Error(`Rule ${n}: ${what} is missing.`);
  return Math.round(t / DAY_MS);
}

function className(value: string, n: number): string {
  const c = value.trim();
  if (!c) throw new Error(`Rule ${n}: a transition's storage class is missing.`);
  return c;
}

function toRule(d: Draft, n: number): LifecycleRule {
  let expiration: LifecycleRule["expiration"] = null;
  if (d.current === "days") expiration = { days: required(d.currentDays, "the days current versions are kept", n) };
  if (d.current === "date") expiration = { date: day(d.currentDate, "the date objects expire from", n) };
  if (d.current === "markers") expiration = { expired_object_delete_marker: true };
  return {
    id: d.id.trim(),
    enabled: d.enabled,
    filter: {
      prefix: d.prefix,
      size_greater_than: number(d.greater, "the smallest size", n),
      size_less_than: number(d.less, "the largest size", n),
      tags: d.tags,
    },
    expiration,
    noncurrent_expiration: d.noncurrent
      ? { days: required(d.noncurrentDays, "the days noncurrent versions are kept", n), newer_versions: number(d.keep, "the versions kept", n) }
      : null,
    abort_upload_days: d.abort ? required(d.abortDays, "the days uploads are kept", n) : null,
    transitions: d.transitions.map((t) =>
      t.by === "date"
        ? { date: day(t.date, "the date of a transition", n), storage_class: className(t.storageClass, n) }
        : { days: required(t.days, "the days before a transition", n), storage_class: className(t.storageClass, n) },
    ),
    noncurrent_transitions: d.noncurrentTransitions.map((t) => ({
      days: required(t.days, "the days before an old version's transition", n),
      newer_versions: number(t.keep, "the versions left", n),
      storage_class: className(t.storageClass, n),
    })),
  };
}

/** `n` days, as typed. */
const days = (n: string) => (n.trim() === "1" ? "1 day" : `${n.trim() || "?"} days`);

/** What a rule does, in a sentence. */
function describe(d: Draft): string {
  let which = d.prefix ? `Objects under "${d.prefix}"` : "All objects";
  if (d.greater.trim()) which += ` larger than ${d.greater.trim()} bytes`;
  if (d.less.trim()) which += `${d.greater.trim() ? " and" : ""} smaller than ${d.less.trim()} bytes`;
  if (d.tags.length) which += ` tagged ${d.tags.map((t) => `${t.key}=${t.value}`).join(", ")}`;
  const what: string[] = [];
  if (d.current === "days") what.push(`expire ${days(d.currentDays)} after they're written`);
  if (d.current === "date") what.push(`expire from ${d.currentDate || "?"} on`);
  if (d.current === "markers") what.push("lose delete markers that are the only version left");
  if (d.noncurrent)
    what.push(
      `lose old versions ${days(d.noncurrentDays)} after they're replaced` +
        (d.keep.trim() ? `, keeping the newest ${d.keep.trim()}` : ""),
    );
  if (d.abort) what.push(`have uploads aborted ${days(d.abortDays)} after they start`);
  for (const t of d.transitions)
    what.push(
      `move to ${t.storageClass.trim() || "?"} ` +
        (t.by === "date" ? `from ${t.date || "?"} on` : `${days(t.days)} after they're written`),
    );
  for (const t of d.noncurrentTransitions)
    what.push(
      `move old versions to ${t.storageClass.trim() || "?"} ${days(t.days)} after they're replaced` +
        (t.keep.trim() ? `, but the newest ${t.keep.trim()}` : ""),
    );
  if (!what.length) return "Does nothing yet: pick at least one action.";
  return `${which}: ${what.join("; ")}.` + (d.enabled ? "" : " (Disabled.)");
}

export default function Lifecycle() {
  const params = useParams();
  const bucket = () => params.bucket ?? "";
  const [drafts, setDrafts] = createSignal<Draft[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [stored, setStored] = createSignal(false);
  const [error, setError] = createSignal<string>();
  // Which objects are too small to transition, as S3 clients set it: kept
  // as it is.
  const [minimum, setMinimum] = createSignal<LifecycleConfiguration["transition_minimum"]>();

  const load = async () => {
    try {
      const l = await api.bucketLifecycle(bucket());
      setDrafts(l.configuration?.rules.map(fromRule) ?? []);
      setMinimum(l.configuration?.transition_minimum);
      setStored(l.configuration != null);
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  createEffect(on(bucket, load));

  const update = (i: number, change: Partial<Draft>) => setDrafts((ds) => ds.map((d, j) => (j === i ? { ...d, ...change } : d)));
  const remove = (i: number) => setDrafts((ds) => ds.filter((_, j) => j !== i));

  const save = async () => {
    const result = await act(async () => {
      const rules = drafts().map((d, i) => toRule(d, i + 1));
      return api.setBucketLifecycle(bucket(), { rules, transition_minimum: minimum() });
    }, "Saved the lifecycle rules; a sweep of them starts now");
    if (result) load();
  };
  const removeAll = async () => {
    if (!confirm(`Remove every lifecycle rule of "${bucket()}"? Nothing expires in it from then on.`)) return;
    if (await act(() => api.deleteBucketLifecycle(bucket()), "Removed the lifecycle rules")) load();
  };

  return (
    <>
      <h1>
        Lifecycle rules of <span class="mono">{bucket()}</span>
      </h1>
      <div class="crumbs">
        <A href="/buckets">Buckets</A>
        <span class="sep">/</span>
        <A href={bucketUrl(bucket())}>{bucket()}</A>
        <span class="sep">/</span>
        <span>lifecycle</span>
      </div>
      <p class="subtle">
        What expires in the bucket, and what moves into colder storage classes, and when, as S3's lifecycle rules say it.
        Rules apply in background sweeps, once a day, at the rate the operator set.{" "}
        Days count to the next midnight UTC. Transitions go only into lower ranked classes (cairn class set --rank), and
        leave out objects under 128 KiB unless the rule filters by size.
      </p>
      <Show when={loaded()} fallback={<Loading error={error()} />}>
        <Show when={drafts().length} fallback={<Panel>{stored() ? "No rules left: save to remove them all." : "This bucket has no lifecycle rules."}</Panel>}>
          <For each={drafts()}>{(d, i) => <RuleEditor draft={d} n={i() + 1} update={(c) => update(i(), c)} remove={() => remove(i())} />}</For>
        </Show>
        <div class="toolbar">
          <button onClick={() => setDrafts((ds) => [...ds, blank()])}>Add rule</button>
          <span class="spacer" />
          <Show when={stored()}>
            <button class="danger" onClick={removeAll}>
              Remove all rules
            </button>
          </Show>
          <button onClick={load}>Discard changes</button>
          <button class="primary" disabled={!drafts().length} onClick={save}>
            Save rules
          </button>
        </div>
      </Show>
    </>
  );
}

function RuleEditor(props: { draft: Draft; n: number; update: (change: Partial<Draft>) => void; remove: () => void }) {
  const d = () => props.draft;
  const input = (key: keyof Draft, placeholder: string, label: string, numeric = true, width?: string) => (
    <input
      type="text"
      inputmode={numeric ? "numeric" : undefined}
      placeholder={placeholder}
      aria-label={label}
      style={width ? { flex: `0 1 ${width}` } : undefined}
      value={d()[key] as string}
      onInput={(e) => props.update({ [key]: e.currentTarget.value })}
    />
  );
  return (
    <Panel
      title={
        <>
          Rule {props.n}
          <span class="subtle">{describe(d())}</span>
        </>
      }
    >
      <div class="rule">
        <div class="form-row">
          <span class="label">Name</span>
          {input("id", "made up if empty", "Rule name", false)}
          <label class="check">
            <input type="checkbox" checked={d().enabled} onChange={(e) => props.update({ enabled: e.currentTarget.checked })} />
            Enabled
          </label>
          <button class="small danger" onClick={props.remove}>
            Remove rule
          </button>
        </div>
        <div class="form-row">
          <span class="label">Objects</span>
          {input("prefix", "key prefix (all keys if empty)", "Key prefix", false)}
          {input("greater", "larger than (bytes)", "Larger than", true, "160px")}
          {input("less", "smaller than (bytes)", "Smaller than", true, "160px")}
        </div>
        <For each={d().tags}>
          {(t, j) => {
            const set = (change: Partial<{ key: string; value: string }>) =>
              props.update({ tags: d().tags.map((u, k) => (k === j() ? { ...u, ...change } : u)) });
            return (
              <div class="form-row">
                <span class="label">{j() === 0 ? "Tagged" : "and"}</span>
                <input type="text" placeholder="tag key" aria-label="Tag key" value={t.key} onInput={(e) => set({ key: e.currentTarget.value })} />
                <span>=</span>
                <input
                  type="text"
                  placeholder="value (may be empty)"
                  aria-label="Tag value"
                  value={t.value}
                  onInput={(e) => set({ value: e.currentTarget.value })}
                />
                <button class="small" onClick={() => props.update({ tags: d().tags.filter((_, k) => k !== j()) })}>
                  Remove tag
                </button>
              </div>
            );
          }}
        </For>
        <div class="form-row">
          <span class="label" />
          <button class="small" onClick={() => props.update({ tags: [...d().tags, { key: "", value: "" }] })}>
            Add tag
          </button>
          <span class="subtle">objects must have every tag, with its value; rules with tags can't abort uploads or remove delete markers</span>
        </div>
        <div class="form-row">
          <span class="label">Current versions</span>
          <select value={d().current} onChange={(e) => props.update({ current: e.currentTarget.value as Draft["current"] })}>
            <option value="none">are kept</option>
            <option value="days">expire after a number of days</option>
            <option value="date">expire from a date on</option>
            <option value="markers">keep, but lone delete markers go</option>
          </select>
          <Show when={d().current === "days"}>
            {input("currentDays", "days", "Days", true, "90px")}
            <span class="subtle">days after they're written</span>
          </Show>
          <Show when={d().current === "date"}>
            <input
              type="date"
              aria-label="Date"
              value={d().currentDate}
              onInput={(e) => props.update({ currentDate: e.currentTarget.value })}
            />
            <span class="subtle">UTC</span>
          </Show>
        </div>
        <div class="form-row">
          <label class="check label">
            <input type="checkbox" checked={d().noncurrent} onChange={(e) => props.update({ noncurrent: e.currentTarget.checked })} />
            Old versions go
          </label>
          <Show when={d().noncurrent}>
            {input("noncurrentDays", "days", "Noncurrent days", true, "90px")}
            <span class="subtle">days after they're replaced, keeping the newest</span>
            {input("keep", "none", "Versions kept", true, "90px")}
          </Show>
        </div>
        <div class="form-row">
          <label class="check label">
            <input type="checkbox" checked={d().abort} onChange={(e) => props.update({ abort: e.currentTarget.checked })} />
            Abort uploads
          </label>
          <Show when={d().abort}>
            {input("abortDays", "days", "Upload days", true, "90px")}
            <span class="subtle">days after they start, if not completed</span>
          </Show>
        </div>
        <For each={d().transitions}>
          {(t, j) => {
            const set = (change: Partial<TransitionDraft>) =>
              props.update({ transitions: d().transitions.map((u, k) => (k === j() ? { ...u, ...change } : u)) });
            return (
              <div class="form-row">
                <span class="label">{j() === 0 ? "Move objects" : "and"}</span>
                <span>to</span>
                <input
                  type="text"
                  placeholder="storage class"
                  aria-label="Storage class"
                  style={{ flex: "0 1 180px" }}
                  value={t.storageClass}
                  onInput={(e) => set({ storageClass: e.currentTarget.value })}
                />
                <select value={t.by} onChange={(e) => set({ by: e.currentTarget.value as TransitionDraft["by"] })}>
                  <option value="days">after a number of days</option>
                  <option value="date">from a date on</option>
                </select>
                <Show
                  when={t.by === "days"}
                  fallback={<input type="date" aria-label="Date" value={t.date} onInput={(e) => set({ date: e.currentTarget.value })} />}
                >
                  <input
                    type="text"
                    inputmode="numeric"
                    placeholder="days"
                    aria-label="Days"
                    style={{ flex: "0 1 90px" }}
                    value={t.days}
                    onInput={(e) => set({ days: e.currentTarget.value })}
                  />
                </Show>
                <button class="small" onClick={() => props.update({ transitions: d().transitions.filter((_, k) => k !== j()) })}>
                  Remove
                </button>
              </div>
            );
          }}
        </For>
        <For each={d().noncurrentTransitions}>
          {(t, j) => {
            const set = (change: Partial<NoncurrentTransitionDraft>) =>
              props.update({ noncurrentTransitions: d().noncurrentTransitions.map((u, k) => (k === j() ? { ...u, ...change } : u)) });
            return (
              <div class="form-row">
                <span class="label">{j() === 0 ? "Move old versions" : "and"}</span>
                <span>to</span>
                <input
                  type="text"
                  placeholder="storage class"
                  aria-label="Storage class"
                  style={{ flex: "0 1 180px" }}
                  value={t.storageClass}
                  onInput={(e) => set({ storageClass: e.currentTarget.value })}
                />
                <input
                  type="text"
                  inputmode="numeric"
                  placeholder="days"
                  aria-label="Noncurrent days"
                  style={{ flex: "0 1 90px" }}
                  value={t.days}
                  onInput={(e) => set({ days: e.currentTarget.value })}
                />
                <span class="subtle">days after they're replaced, but the newest</span>
                <input
                  type="text"
                  inputmode="numeric"
                  placeholder="none"
                  aria-label="Versions left"
                  style={{ flex: "0 1 90px" }}
                  value={t.keep}
                  onInput={(e) => set({ keep: e.currentTarget.value })}
                />
                <button
                  class="small"
                  onClick={() => props.update({ noncurrentTransitions: d().noncurrentTransitions.filter((_, k) => k !== j()) })}
                >
                  Remove
                </button>
              </div>
            );
          }}
        </For>
        <div class="form-row">
          <span class="label" />
          <button
            class="small"
            onClick={() => props.update({ transitions: [...d().transitions, { by: "days", days: "30", date: "", storageClass: "" }] })}
          >
            Add transition
          </button>
          <button
            class="small"
            onClick={() =>
              props.update({ noncurrentTransitions: [...d().noncurrentTransitions, { days: "30", keep: "", storageClass: "" }] })
            }
          >
            Add transition of old versions
          </button>
          <span class="subtle">into a lower ranked storage class</span>
        </div>
      </div>
    </Panel>
  );
}
