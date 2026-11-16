// A bucket's event notifications: S3's notification configuration, rules
// that send the events of keys with a prefix and suffix to SNS topics (see
// `src/notifications`). The server checks them as S3 does, the topics'
// policies too: each must let S3 publish the bucket's events.

import { A, useParams } from "@solidjs/router";
import { For, Show, createEffect, createSignal, on } from "solid-js";
import { type NotificationRule, type Topic, api } from "../api";
import { Loading, Panel, act } from "../components/ui";
import { bucketUrl } from "./Buckets";
import { topicHref } from "./Topics";

/** The events offered first; the rest are under "more". */
const COMMON: [string, string][] = [
  ["s3:ObjectCreated:*", "Objects created (put, POST, copy, multipart)"],
  ["s3:ObjectRemoved:*", "Objects deleted (and delete markers)"],
  ["s3:ObjectTagging:*", "Objects' tags set or deleted"],
  ["s3:LifecycleExpiration:*", "Expired by lifecycle rules"],
];

/** The events Cairn makes: the others are taken, as S3 takes them, but
 * never happen. */
const MADE = new Set([
  "s3:ObjectCreated:*",
  "s3:ObjectCreated:Put",
  "s3:ObjectCreated:Post",
  "s3:ObjectCreated:Copy",
  "s3:ObjectCreated:CompleteMultipartUpload",
  "s3:ObjectRemoved:*",
  "s3:ObjectRemoved:Delete",
  "s3:ObjectRemoved:DeleteMarkerCreated",
  "s3:ObjectTagging:*",
  "s3:ObjectTagging:Put",
  "s3:ObjectTagging:Delete",
  "s3:LifecycleExpiration:*",
  "s3:LifecycleExpiration:Delete",
  "s3:LifecycleExpiration:DeleteMarkerCreated",
]);

const blank = (): NotificationRule => ({ id: "", topic_arn: "", events: ["s3:ObjectCreated:*"], prefix: "", suffix: "" });

export default function Notifications() {
  const params = useParams();
  const bucket = () => params.bucket ?? "";
  const [rules, setRules] = createSignal<NotificationRule[]>([]);
  const [events, setEvents] = createSignal<string[]>([]);
  const [topics, setTopics] = createSignal<Topic[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [error, setError] = createSignal<string>();

  const load = async () => {
    try {
      const n = await api.bucketNotifications(bucket());
      setRules(n.rules.map((r) => ({ ...r, events: [...r.events] })));
      setEvents(n.events ?? []);
      setTopics(await api.topics().catch(() => []));
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  createEffect(on(bucket, load));

  const update = (i: number, change: Partial<NotificationRule>) => setRules((rs) => rs.map((r, j) => (j === i ? { ...r, ...change } : r)));
  const save = async () => {
    const done = await act(
      () => api.setBucketNotifications(bucket(), rules()),
      rules().length ? "Saved; each rule's topic was sent S3's test event" : "Removed the notifications",
    );
    if (done) load();
  };

  return (
    <>
      <h1>
        Event notifications of <span class="mono">{bucket()}</span>
      </h1>
      <div class="crumbs">
        <A href="/buckets">Buckets</A>
        <span class="sep">/</span>
        <A href={bucketUrl(bucket())}>{bucket()}</A>
        <span class="sep">/</span>
        <span>notifications</span>
      </div>
      <p class="subtle">
        Each rule sends the events of the bucket's keys it matches to an SNS topic, as S3's notification configuration
        does. The topic's policy must let S3 publish this bucket's events (its page adds that statement); two rules
        can't share an event for overlapping keys.
      </p>
      <Show when={loaded()} fallback={<Loading error={error()} />}>
        <Show when={rules().length} fallback={<Panel>This bucket sends no events.</Panel>}>
          <For each={rules()}>
            {(r, i) => (
              <RuleEditor rule={r} n={i() + 1} events={events()} topics={topics()} update={(c) => update(i(), c)} remove={() => setRules((rs) => rs.filter((_, j) => j !== i()))} />
            )}
          </For>
        </Show>
        <div class="toolbar">
          <button onClick={() => setRules((rs) => [...rs, blank()])}>Add rule</button>
          <span class="spacer" />
          <button onClick={load}>Discard changes</button>
          <button class="primary" onClick={save}>
            Save rules
          </button>
        </div>
      </Show>
    </>
  );
}

function RuleEditor(props: {
  rule: NotificationRule;
  n: number;
  events: string[];
  topics: Topic[];
  update: (change: Partial<NotificationRule>) => void;
  remove: () => void;
}) {
  const r = () => props.rule;
  const has = (e: string) => r().events.includes(e);
  const toggle = (e: string, on: boolean) => props.update({ events: on ? [...r().events, e] : r().events.filter((x) => x !== e) });
  const [more, setMore] = createSignal(r().events.some((e) => !COMMON.some(([c]) => c === e)));
  const topicName = () => r().topic_arn.split(":").pop() ?? "";
  return (
    <Panel title={<>Rule {props.n}</>}>
      <div class="rule">
        <div class="form-row">
          <span class="label">Name</span>
          <input type="text" placeholder="made up if empty" aria-label="Rule name" value={r().id} onInput={(e) => props.update({ id: e.currentTarget.value })} />
          <button class="small danger" onClick={props.remove}>
            Remove rule
          </button>
        </div>
        <div class="form-row">
          <span class="label">Topic</span>
          <select aria-label="Topic" value={r().topic_arn} onChange={(e) => props.update({ topic_arn: e.currentTarget.value })}>
            <option value="">Choose a topic…</option>
            <For each={props.topics}>{(t) => <option value={t.arn}>{t.name}</option>}</For>
            <Show when={r().topic_arn && !props.topics.some((t) => t.arn === r().topic_arn)}>
              <option value={r().topic_arn}>{r().topic_arn} (gone, or not yours to see)</option>
            </Show>
          </select>
          <Show when={topicName()}>
            <A href={topicHref(topicName())}>open</A>
          </Show>
        </div>
        <div class="form-row">
          <span class="label">Keys</span>
          <input type="text" placeholder="prefix (all keys if empty)" aria-label="Key prefix" value={r().prefix} onInput={(e) => props.update({ prefix: e.currentTarget.value })} />
          <input type="text" placeholder="suffix (.jpg, ...)" aria-label="Key suffix" value={r().suffix} onInput={(e) => props.update({ suffix: e.currentTarget.value })} />
        </div>
        <div class="form-row">
          <span class="label">Events</span>
          <div>
            <For each={COMMON}>
              {([e, label]) => (
                <label class="check">
                  <input type="checkbox" checked={has(e)} onChange={(ev) => toggle(e, ev.currentTarget.checked)} />
                  {label}
                </label>
              )}
            </For>
            <label class="check">
              <input type="checkbox" checked={more()} onChange={(e) => setMore(e.currentTarget.checked)} />
              More…
            </label>
            <Show when={more()}>
              <For each={props.events.filter((e) => !COMMON.some(([c]) => c === e))}>
                {(e) => (
                  <label class="check mono small" title={MADE.has(e) ? undefined : "S3 takes it, but Cairn never makes this event"}>
                    <input type="checkbox" checked={has(e)} onChange={(ev) => toggle(e, ev.currentTarget.checked)} />
                    {e}
                    {MADE.has(e) ? "" : " (never happens)"}
                  </label>
                )}
              </For>
            </Show>
          </div>
        </div>
      </div>
    </Panel>
  );
}
