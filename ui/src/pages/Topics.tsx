// SNS's topics (see `src/sns`): where buckets' event notifications go, and
// their subscriptions, HTTP(S) endpoints that are sent each message, signed
// as SNS signs them. Everything here is SNS's own actions, as the signed-in
// identity: what its policies (and the topic's) allow.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type TopicDetail, api } from "../api";
import { DetailHead, Gone, TagChips } from "../components/Iam";
import { TagsDialog } from "../components/Editors";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { pretty } from "../format";

export const topicHref = (name: string) => `/topics/${encodeURIComponent(name)}`;

export default function Topics() {
  const topics = poll(() => api.topics(), 10000);
  const [creating, setCreating] = createSignal(false);
  return (
    <>
      <div class="page-head">
        <h1>Topics</h1>
        <button class="primary" onClick={() => setCreating(true)}>
          New topic
        </button>
      </div>
      <p class="subtle small">
        SNS topics, as S3's event notifications use them: a bucket's notification rules send its events (objects
        written, deleted, tagged, expired) to topics, and a topic sends each message to its confirmed subscriptions,
        HTTP(S) endpoints, signed as SNS signs them. Tools for SNS work with them too (<span class="mono">aws sns</span>,
        Terraform's <span class="mono">aws_sns_topic</span>), at the S3 endpoint.
      </p>
      <Show when={topics.data()} fallback={<Loading error={topics.error()} />}>
        {(list) => (
          <Panel>
            <Table count={list().length} empty="No topics yet." columns={["Name", "Display name", { label: "Subscriptions", num: true }]}>
              <For each={list()}>
                {(t) => (
                  <tr>
                    <td>
                      <A class="mono" href={topicHref(t.name)}>
                        {t.name}
                      </A>
                    </td>
                    <td>{t.display_name}</td>
                    <td class="num">
                      {t.subscriptions_confirmed}
                      <Show when={t.subscriptions_pending}>
                        {" "}
                        <Badge tone="warn">{t.subscriptions_pending} pending</Badge>
                      </Show>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={creating()}>
        <NewTopicDialog onClose={() => setCreating(false)} changed={topics.refresh} />
      </Show>
    </>
  );
}

function NewTopicDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const navigate = useNavigate();
  const [name, setName] = createSignal("");
  const [display, setDisplay] = createSignal("");
  const [error, setError] = createSignal<string>();
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.createTopic(n, display().trim());
    } catch (e) {
      setError((e as Error).message);
      return;
    }
    toast(`Created topic ${n}`);
    props.changed();
    dialog.close();
    navigate(topicHref(n));
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={create}>
        <h2>New topic</h2>
        <input type="text" placeholder="topic-name" aria-label="Topic name" autocomplete="off" required value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        <input type="text" placeholder="display name (optional)" aria-label="Display name" value={display()} onInput={(e) => setDisplay(e.currentTarget.value)} />
        <p class="subtle small">Letters, digits, hyphens and underscores, up to 256 of them.</p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Create topic
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** A statement letting S3 publish the events of `buckets` (a name, or a
 * pattern) to the topic, added to its policy. */
function withS3Statement(policy: string, arn: string, buckets: string): string {
  const doc = JSON.parse(policy);
  const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
  statements.push({
    Sid: `S3Events-${buckets.replace(/[^A-Za-z0-9]/g, "")}`,
    Effect: "Allow",
    Principal: { Service: "s3.amazonaws.com" },
    Action: "SNS:Publish",
    Resource: arn,
    Condition: { ArnLike: { "aws:SourceArn": `arn:aws:s3:::${buckets}` } },
  });
  doc.Statement = statements;
  return JSON.stringify(doc, null, 2);
}

export function TopicPage() {
  const params = useParams();
  const name = () => params.name ?? "";
  const navigate = useNavigate();
  const topic = poll(() => api.topic(name()), 10000);
  const [tagging, setTagging] = createSignal(false);
  const [gone, setGone] = createSignal(false);
  const remove = async () => {
    if (!confirm(`Delete topic "${name()}" and its subscriptions? Buckets' rules naming it stay, and their events are dropped.`)) return;
    if (await act(() => api.deleteTopic(name()), `Deleted topic ${name()}`)) navigate("/topics");
  };
  const load = async () => {
    try {
      await api.topic(name());
    } catch {
      setGone(true);
    }
  };
  onMount(load);
  return (
    <Show when={!gone()} fallback={<Gone kind="Topics" href="/topics" name={name()} />}>
      <DetailHead kind="Topics" href="/topics" name={name()}>
        <button onClick={() => setTagging(true)}>Tags</button>
        <button class="danger" onClick={remove}>
          Delete topic
        </button>
      </DetailHead>
      <Show when={topic.data()} fallback={<Loading error={topic.error()} />}>
        {(t) => (
          <>
            <p class="subtle small mono">{t().arn}</p>
            <Settings topic={t()} changed={topic.refresh} />
            <Subscriptions topic={t()} changed={topic.refresh} />
            <PublishPanel topic={t()} />
            <PolicyPanel topic={t()} changed={topic.refresh} />
            <DeliveryPanel topic={t()} changed={topic.refresh} />
            <Panel title="Tags">
              <TagChips tags={t().tags} />
            </Panel>
            <Show when={tagging()}>
              <TagsDialog
                title={`Tags of ${name()}`}
                tags={t().tags}
                save={(tags) => api.setTopicTags(name(), tags)}
                onClose={() => setTagging(false)}
                changed={topic.refresh}
              />
            </Show>
          </>
        )}
      </Show>
    </Show>
  );
}

function Settings(props: { topic: TopicDetail; changed: () => void }) {
  const [display, setDisplay] = createSignal(props.topic.display_name);
  const [version, setVersion] = createSignal(props.topic.signature_version);
  const save = async () => {
    if (await act(() => api.setTopicSettings(props.topic.name, display().trim(), version()), "Saved")) props.changed();
  };
  return (
    <Panel title="Settings">
      <div class="form-row">
        <span class="label">Display name</span>
        <input type="text" aria-label="Display name" value={display()} onInput={(e) => setDisplay(e.currentTarget.value)} />
      </div>
      <div class="form-row">
        <span class="label">Signatures</span>
        <select aria-label="Signature version" value={String(version())} onChange={(e) => setVersion(Number(e.currentTarget.value))}>
          <option value="1">Version 1 (SHA1, SNS's default)</option>
          <option value="2">Version 2 (SHA256)</option>
        </select>
        <button class="primary" onClick={save}>
          Save
        </button>
      </div>
    </Panel>
  );
}

function Subscriptions(props: { topic: TopicDetail; changed: () => void }) {
  const [protocol, setProtocol] = createSignal("https");
  const [endpoint, setEndpoint] = createSignal("");
  const subscribe = async (e: SubmitEvent) => {
    e.preventDefault();
    const done = await act(
      () => api.subscribe(props.topic.name, protocol(), endpoint().trim()),
      "Subscribed: the endpoint was sent a confirmation, which it must confirm",
    );
    if (done) {
      setEndpoint("");
      props.changed();
    }
  };
  const unsubscribe = async (arn: string) => {
    if (!confirm("Unsubscribe this endpoint? It's sent nothing more.")) return;
    if (await act(() => api.unsubscribe(props.topic.name, arn), "Unsubscribed")) props.changed();
  };
  const state = (arn: string) =>
    arn === "PendingConfirmation" ? <Badge tone="warn">pending confirmation</Badge> : arn === "Deleted" ? <Badge>unsubscribed</Badge> : <Badge tone="ok">confirmed</Badge>;
  return (
    <Panel
      title="Subscriptions"
      note="Each is sent a confirmation first, with a SubscribeURL to visit (or a token for ConfirmSubscription); only confirmed ones get messages."
    >
      <Table count={props.topic.subscriptions.length} empty="No subscriptions yet." columns={["Endpoint", "State", ""]}>
        <For each={props.topic.subscriptions}>
          {(s) => (
            <tr>
              <td class="mono">{s.endpoint}</td>
              <td>{state(s.arn)}</td>
              <td class="num">
                <Show when={s.arn.startsWith("arn:")}>
                  <button class="small" onClick={() => unsubscribe(s.arn)}>
                    Unsubscribe
                  </button>
                </Show>
              </td>
            </tr>
          )}
        </For>
      </Table>
      <form class="form-row" onSubmit={subscribe}>
        <select aria-label="Protocol" value={protocol()} onChange={(e) => setProtocol(e.currentTarget.value)}>
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
        <input type="text" placeholder={`${protocol()}://example.com/hook`} aria-label="Endpoint" required value={endpoint()} onInput={(e) => setEndpoint(e.currentTarget.value)} />
        <button class="primary" type="submit">
          Subscribe
        </button>
      </form>
    </Panel>
  );
}

function PublishPanel(props: { topic: TopicDetail }) {
  const [subject, setSubject] = createSignal("");
  const [message, setMessage] = createSignal("");
  const publish = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.publish(props.topic.name, message(), subject().trim()), "Published")) setMessage("");
  };
  return (
    <Panel title="Publish a message" note="To try the subscriptions: it's sent to each confirmed one.">
      <form onSubmit={publish}>
        <div class="form-row">
          <input type="text" placeholder="subject (optional)" aria-label="Subject" value={subject()} onInput={(e) => setSubject(e.currentTarget.value)} />
        </div>
        <textarea rows={3} aria-label="Message" required value={message()} onInput={(e) => setMessage(e.currentTarget.value)} />
        <div class="buttons">
          <button type="submit">Publish</button>
        </div>
      </form>
    </Panel>
  );
}

function PolicyPanel(props: { topic: TopicDetail; changed: () => void }) {
  const [text, setText] = createSignal(pretty(props.topic.policy));
  const [buckets, setBuckets] = createSignal("");
  const save = async () => {
    if (await act(() => api.setTopicPolicy(props.topic.name, text()), "Saved the policy")) props.changed();
  };
  const allowS3 = () => {
    const b = buckets().trim();
    if (!b) return toast("Name a bucket (or a pattern, logs-*) first", true);
    try {
      setText(withS3Statement(text(), props.topic.arn, b));
    } catch (e) {
      toast(`The policy isn't JSON: ${(e as Error).message}`, true);
    }
  };
  return (
    <Panel
      title="Policy"
      note="Who may do what with the topic, besides their own policies. S3 publishes a bucket's events only if this lets s3.amazonaws.com publish them: add a statement for the bucket below."
    >
      <div class="form-row">
        <input type="text" placeholder="bucket, or a pattern (logs-*)" aria-label="Bucket" value={buckets()} onInput={(e) => setBuckets(e.currentTarget.value)} />
        <button onClick={allowS3}>Let S3 publish its events</button>
      </div>
      <textarea class="mono" rows={14} aria-label="Policy" value={text()} onInput={(e) => setText(e.currentTarget.value)} />
      <div class="buttons">
        <button onClick={() => setText(pretty(props.topic.policy))}>Discard changes</button>
        <button class="primary" onClick={save}>
          Save policy
        </button>
      </div>
    </Panel>
  );
}

function DeliveryPanel(props: { topic: TopicDetail; changed: () => void }) {
  const [text, setText] = createSignal(props.topic.delivery_policy ? pretty(props.topic.delivery_policy) : "");
  const save = async () => {
    const done = await act(
      () => api.setTopicDeliveryPolicy(props.topic.name, text().trim()),
      text().trim() ? "Saved the delivery policy" : "Removed the delivery policy",
    );
    if (done) props.changed();
  };
  return (
    <Panel
      title="Delivery policy"
      note="How often, and how far apart, a failed delivery is retried (SNS's DeliveryPolicy). Empty: SNS's default, three retries 20 seconds apart."
    >
      <textarea class="mono" rows={8} aria-label="Delivery policy" placeholder='{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":600,"numRetries":10,"backoffFunction":"exponential"}}}' value={text()} onInput={(e) => setText(e.currentTarget.value)} />
      <p class="subtle small">
        In effect: <span class="mono">{props.topic.effective_delivery_policy}</span>
      </p>
      <div class="buttons">
        <button class="primary" onClick={save}>
          Save delivery policy
        </button>
      </div>
    </Panel>
  );
}
