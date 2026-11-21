// CloudTrail (see `src/cloudtrail.rs`): the account's event history, every
// audited call (the KMS's, CloudTrail's own) as CloudTrail records it, and
// its trails, which deliver the events to a bucket as CloudTrail's log
// files. Everything here is CloudTrail's own operations, as the signed-in
// identity: what its policies allow. And each is recorded itself, as made
// through the console.

import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type Trail, type TrailDetail, type TrailEvent, type TrailStatus, api } from "../api";
import { DetailHead, Gone, TagChips } from "../components/Iam";
import { TagsDialog } from "../components/Editors";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { ago, date, pretty } from "../format";
import { api as session } from "../session";

export const trailHref = (name: string) => `/trails/${encodeURIComponent(name)}`;

/** The event history's page, looking events up by `attribute` = `value`. */
export const eventsHref = (attribute: string, value: string) =>
  `/event-history?${new URLSearchParams({ attribute, value })}`;

// ─── Event history ──────────────────────────────────────────────────────────

/** What events may be looked up by, as LookupEvents has them. */
const ATTRIBUTES: [string, string][] = [
  ["EventName", "Event name"],
  ["Username", "User name"],
  ["ResourceName", "Resource name (ARN)"],
  ["ResourceType", "Resource type"],
  ["EventSource", "Event source"],
  ["EventId", "Event ID"],
  ["ReadOnly", "Read-only (true, false)"],
  ["AccessKeyId", "Access key ID"],
];

/** How far back to look, in seconds. */
const RANGES: [number, string][] = [
  [3600, "Last hour"],
  [86400, "Last 24 hours"],
  [7 * 86400, "Last 7 days"],
  [90 * 86400, "Last 90 days"],
];

/** The most events a lookup shows before asking for more, and how many
 * pages it reads to get them (a page may have few, or none, and go on). */
const WANTED = 50;
const MAX_PAGES = 6;

type Lookup = { attribute?: string; value?: string; start: number };

export function EventHistory() {
  const [params, setParams] = useSearchParams();
  const param = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) ?? "";
  const [attribute, setAttribute] = createSignal(param(params.attribute) || "EventName");
  const [value, setValue] = createSignal(param(params.value));
  const [range, setRange] = createSignal(90 * 86400);
  const [events, setEvents] = createSignal<TrailEvent[]>();
  const [next, setNext] = createSignal<string>();
  const [error, setError] = createSignal<string>();
  const [busy, setBusy] = createSignal(false);
  const [open, setOpen] = createSignal<string>();
  // The lookup the pages are of: a NextToken is only that lookup's.
  let lookup: Lookup = { start: 0 };

  /** Reads pages from `token` on (from the newest if none), until there
   * are enough events or no more. */
  const read = async (token: string | undefined, have: TrailEvent[]) => {
    setBusy(true);
    try {
      let found = have;
      for (let pages = 0; pages < MAX_PAGES; pages++) {
        const page = await api.events({ ...lookup, next_token: token });
        found = [...found, ...page.events];
        token = page.next_token ?? undefined;
        if (!token || found.length - have.length >= WANTED) break;
      }
      setEvents(found);
      setNext(token);
      setError(undefined);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const search = (e?: SubmitEvent) => {
    e?.preventDefault();
    const v = value().trim();
    setParams({ attribute: v ? attribute() : undefined, value: v || undefined });
    lookup = {
      ...(v ? { attribute: attribute(), value: v } : {}),
      start: Math.floor(Date.now() / 1000) - range(),
    };
    setOpen(undefined);
    read(undefined, []);
  };
  /** Looks events up by `a` = `v`. */
  const by = (a: string, v: string) => {
    setAttribute(a);
    setValue(v);
    search();
  };
  onMount(() => search());

  return (
    <>
      <div class="page-head">
        <h1>Event history</h1>
        <button onClick={() => search()} disabled={busy()}>
          Refresh
        </button>
      </div>
      <p class="subtle small">
        The account's audited calls, as CloudTrail records them: every call to the KMS's API and to CloudTrail's (these
        pages' too), with who made it, from where, and how it went. An event is here within about five minutes of its
        call, and kept for 90 days. Tools for CloudTrail read the same (<span class="mono">aws cloudtrail lookup-events</span>),
        at the S3 endpoint; <A href="/trails">trails</A> deliver the events to a bucket.
      </p>
      <Panel>
        <form class="toolbar" onSubmit={search}>
          <select aria-label="Look up by" value={attribute()} onChange={(e) => setAttribute(e.currentTarget.value)}>
            <For each={ATTRIBUTES}>{([key, label]) => <option value={key}>{label}</option>}</For>
          </select>
          <input
            type="text"
            placeholder="value (exactly; empty for every event)"
            aria-label="Value"
            value={value()}
            onInput={(e) => setValue(e.currentTarget.value)}
          />
          <select aria-label="Time range" value={String(range())} onChange={(e) => setRange(Number(e.currentTarget.value))}>
            <For each={RANGES}>{([secs, label]) => <option value={String(secs)}>{label}</option>}</For>
          </select>
          <button class="primary" type="submit" disabled={busy()}>
            Look up
          </button>
          <Show when={value()}>
            <button
              type="button"
              onClick={() => {
                setValue("");
                search();
              }}
            >
              Clear
            </button>
          </Show>
        </form>
        <Show when={events()} fallback={<Loading error={error()} />}>
          {(list) => (
            <>
              <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
              <Table
                count={list().length}
                empty={next() ? "None found yet: look further back." : "No events."}
                columns={["Time", "Event", "User", "Source", "Resources", "Outcome"]}
              >
                <For each={list()}>
                  {(e) => (
                    <>
                      <tr class="clickable" onClick={() => setOpen(open() === e.id ? undefined : e.id)}>
                        <td class="nowrap" title={e.id}>
                          {date(e.time)}
                        </td>
                        <td>
                          <a
                            href={eventsHref("EventName", e.name)}
                            onClick={(ev) => {
                              ev.preventDefault();
                              ev.stopPropagation();
                              by("EventName", e.name);
                            }}
                          >
                            {e.name}
                          </a>{" "}
                          <Show when={e.read_only}>
                            <Badge>read</Badge>
                          </Show>
                        </td>
                        <td>
                          <Show when={e.username} fallback={<span class="subtle">–</span>}>
                            {(u) => (
                              <a
                                class="mono"
                                href={eventsHref("Username", u())}
                                onClick={(ev) => {
                                  ev.preventDefault();
                                  ev.stopPropagation();
                                  by("Username", u());
                                }}
                              >
                                {u()}
                              </a>
                            )}
                          </Show>
                          <Show when={e.console}>
                            {" "}
                            <Badge tone="accent">console</Badge>
                          </Show>
                        </td>
                        <td class="small">
                          <div class="mono">{e.source.replace(/\.amazonaws\.com$/, "")}</div>
                          <div class="subtle mono">{e.source_ip}</div>
                        </td>
                        <td class="small mono">
                          <For each={e.resources}>{(r) => <div title={r.kind ?? ""}>{shortArn(r.name ?? "")}</div>}</For>
                        </td>
                        <td>
                          <Show when={e.error_code} fallback={<Badge tone="ok">ok</Badge>}>
                            {(code) => (
                              <span title={e.error_message ?? ""}>
                                <Badge tone="bad">{code()}</Badge>
                              </span>
                            )}
                          </Show>
                        </td>
                      </tr>
                      <Show when={open() === e.id}>
                        <tr>
                          <td colspan={6}>
                            <div class="pem">{pretty(e.record)}</div>
                          </td>
                        </tr>
                      </Show>
                    </>
                  )}
                </For>
              </Table>
              <Show when={next()}>
                {(token) => (
                  <div class="buttons">
                    <button onClick={() => read(token(), list())} disabled={busy()}>
                      {busy() ? "Looking…" : "Load more"}
                    </button>
                  </div>
                )}
              </Show>
            </>
          )}
        </Show>
      </Panel>
    </>
  );
}

/** An ARN's resource part (`key/1234…`), for a narrow column. */
function shortArn(arn: string): string {
  const parts = arn.split(":");
  return parts.length >= 6 ? parts.slice(5).join(":") : arn;
}

// ─── Trails ─────────────────────────────────────────────────────────────────

/** A trail's status, as a badge. */
function StatusBadge(props: { status?: TrailStatus | null }) {
  return (
    <Show when={props.status} fallback={<span class="subtle">–</span>}>
      {(s) => (
        <Show when={s().logging} fallback={<Badge>stopped</Badge>}>
          <Show when={s().error} fallback={<Badge tone="ok">logging</Badge>}>
            <Badge tone="bad">delivery failing</Badge>
          </Show>
        </Show>
      )}
    </Show>
  );
}

/** Where a trail's files go: its bucket and prefix. */
const destination = (t: { bucket: string; prefix?: string | null }) => (t.prefix ? `${t.bucket}/${t.prefix}` : t.bucket);

export default function Trails() {
  // Each look is CloudTrail's DescribeTrails and GetTrailStatus, and
  // recorded: refreshed by hand, not every few seconds.
  const trails = poll(() => api.trails());
  const [creating, setCreating] = createSignal(false);
  return (
    <>
      <div class="page-head">
        <h1>Trails</h1>
        <div class="buttons">
          <button onClick={() => trails.refresh()}>Refresh</button>
          <button class="primary" onClick={() => setCreating(true)}>
            New trail
          </button>
        </div>
      </div>
      <p class="subtle small">
        A trail delivers the account's <A href="/event-history">events</A> to a bucket, as CloudTrail's log files
        (gzipped JSON, at <span class="mono">AWSLogs/&lt;account&gt;/CloudTrail/…</span>), so that tools that read
        CloudTrail's read them too. It delivers every five minutes, about half a minute after the clock's marks, while
        it's logging; the bucket's policy must let <span class="mono">cloudtrail.amazonaws.com</span> write to it. At
        most five an account.
      </p>
      <Show when={trails.data()} fallback={<Loading error={trails.error()} />}>
        {(list) => (
          <Panel>
            <Table count={list().length} empty="No trails yet." columns={["Name", "Delivers to", "Status", "Last delivery"]}>
              <For each={list()}>{(t) => <TrailRow trail={t} />}</For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={creating()}>
        <NewTrailDialog onClose={() => setCreating(false)} changed={trails.refresh} />
      </Show>
    </>
  );
}

function TrailRow(props: { trail: Trail }) {
  const t = () => props.trail;
  return (
    <tr>
      <td>
        <A class="mono" href={trailHref(t().name)}>
          {t().name}
        </A>
      </td>
      <td class="mono">{destination(t())}</td>
      <td>
        <StatusBadge status={t().status} />
      </td>
      <td title={t().status?.error ?? ""}>{t().status ? ago(t().status?.delivered) : "–"}</td>
    </tr>
  );
}

/** The statements of CloudTrail's example bucket policy, for the trail
 * `name` of `account` delivering to `bucket` with `prefix`. */
function cloudTrailStatements(bucket: string, prefix: string, account: string, name: string) {
  const arn = `arn:aws:cloudtrail:*:${account}:trail/${name}`;
  const path = prefix ? `${prefix.replace(/\/+$/, "")}/` : "";
  const sid = name.replace(/[^A-Za-z0-9]/g, "");
  return [
    {
      Sid: `AWSCloudTrailAclCheck${sid}`,
      Effect: "Allow",
      Principal: { Service: "cloudtrail.amazonaws.com" },
      Action: "s3:GetBucketAcl",
      Resource: `arn:aws:s3:::${bucket}`,
      Condition: { ArnLike: { "aws:SourceArn": arn } },
    },
    {
      Sid: `AWSCloudTrailWrite${sid}`,
      Effect: "Allow",
      Principal: { Service: "cloudtrail.amazonaws.com" },
      Action: "s3:PutObject",
      Resource: `arn:aws:s3:::${bucket}/${path}AWSLogs/${account}/*`,
      Condition: {
        StringEquals: { "s3:x-amz-acl": "bucket-owner-full-control" },
        ArnLike: { "aws:SourceArn": arn },
      },
    },
  ];
}

/** Adds CloudTrail's statements (see `cloudTrailStatements`) to `bucket`'s
 * policy, in place of any it has of the same names. */
async function allowCloudTrail(bucket: string, prefix: string, name: string) {
  const me = await session.me();
  const account = me.identity.account_id;
  const { policy } = await api.bucketAccess(bucket);
  const doc = policy ? JSON.parse(policy) : { Version: "2012-10-17", Statement: [] };
  const added = cloudTrailStatements(bucket, prefix, account, name);
  const statements = (Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : []).filter(
    (s: { Sid?: string }) => !added.some((a) => a.Sid === s.Sid),
  );
  doc.Statement = [...statements, ...added];
  await api.putBucketPolicy(bucket, JSON.stringify(doc, null, 2));
}

function NewTrailDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const navigate = useNavigate();
  const buckets = poll(() => api.buckets());
  const [name, setName] = createSignal("");
  const [bucket, setBucket] = createSignal("");
  const [prefix, setPrefix] = createSignal("");
  const [key, setKey] = createSignal("");
  const [multiRegion, setMultiRegion] = createSignal(true);
  const [start, setStart] = createSignal(true);
  const [allow, setAllow] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [busy, setBusy] = createSignal(false);
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    setBusy(true);
    try {
      if (allow()) await allowCloudTrail(bucket().trim(), prefix().trim(), n);
      await api.createTrail({
        name: n,
        bucket: bucket().trim(),
        prefix: prefix().trim(),
        kms_key_id: key().trim(),
        multi_region: multiRegion(),
        include_global: true,
        start_logging: start(),
      });
    } catch (e) {
      setError((e as Error).message);
      return;
    } finally {
      setBusy(false);
    }
    toast(`Created trail ${n}`);
    props.changed();
    dialog.close();
    navigate(trailHref(n));
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={create}>
        <h2>New trail</h2>
        <input type="text" placeholder="trail-name" aria-label="Trail name" autocomplete="off" required value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        <p class="subtle small">3 to 128 letters, digits, periods, underscores and dashes, starting and ending with a letter or digit.</p>
        <input type="text" placeholder="bucket" aria-label="Bucket" list="trail-buckets" required value={bucket()} onInput={(e) => setBucket(e.currentTarget.value)} />
        <datalist id="trail-buckets">
          <For each={buckets.data() ?? []}>{(b) => <option value={b.name} />}</For>
        </datalist>
        <input type="text" placeholder="key prefix (optional)" aria-label="Key prefix" value={prefix()} onInput={(e) => setPrefix(e.currentTarget.value)} />
        <input type="text" placeholder="KMS key to encrypt with (optional: ID, ARN or alias/…)" aria-label="KMS key" value={key()} onInput={(e) => setKey(e.currentTarget.value)} />
        <label class="check">
          <input type="checkbox" checked={allow()} onChange={(e) => setAllow(e.currentTarget.checked)} />
          Add CloudTrail's statements to the bucket's policy
        </label>
        <p class="subtle small">
          The bucket's policy must let <span class="mono">cloudtrail.amazonaws.com</span> read its ACL and write the
          trail's files: this adds CloudTrail's example statements for this trail (as yours, through the bucket's
          policy).
        </p>
        <label class="check">
          <input type="checkbox" checked={multiRegion()} onChange={(e) => setMultiRegion(e.currentTarget.checked)} />
          Multi-region (Cairn has one region: kept as it's set)
        </label>
        <label class="check">
          <input type="checkbox" checked={start()} onChange={(e) => setStart(e.currentTarget.checked)} />
          Start logging
        </label>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={busy()}>
            Create trail
          </button>
        </div>
      </form>
    </dialog>
  );
}

export function TrailPage() {
  const params = useParams();
  const name = () => params.name ?? "";
  const navigate = useNavigate();
  const trail = poll(() => api.trail(name()));
  const [tagging, setTagging] = createSignal(false);
  // Each look is four of CloudTrail's calls, each recorded: no other.
  const gone = () => !trail.data() && trail.error() !== undefined;
  const remove = async () => {
    if (!confirm(`Delete trail "${name()}"? It delivers nothing more; the files it delivered stay.`)) return;
    if (await act(() => api.deleteTrail(name()), `Deleted trail ${name()}`)) navigate("/trails");
  };
  return (
    <Show when={!gone()} fallback={<Gone kind="Trails" href="/trails" name={name()} />}>
      <DetailHead kind="Trails" href="/trails" name={name()}>
        <button onClick={() => trail.refresh()}>Refresh</button>
        <Show when={trail.data()?.tags}>
          <button onClick={() => setTagging(true)}>Tags</button>
        </Show>
        <button class="danger" onClick={remove}>
          Delete trail
        </button>
      </DetailHead>
      <Show when={trail.data()} fallback={<Loading error={trail.error()} />}>
        {(t) => (
          <>
            <p class="subtle small mono">{t().arn}</p>
            <StatusPanel trail={t()} changed={trail.refresh} />
            <SettingsPanel trail={t()} changed={trail.refresh} />
            <Show when={t().selectors}>{(s) => <SelectorsPanel trail={t()} selectors={s()} changed={trail.refresh} />}</Show>
            <Show when={t().tags}>
              {(tags) => (
                <>
                  <Panel title="Tags">
                    <TagChips tags={tags()} />
                  </Panel>
                  <Show when={tagging()}>
                    <TagsDialog
                      title={`Tags of ${name()}`}
                      tags={tags()}
                      save={(tags) => api.setTrailTags(name(), tags)}
                      onClose={() => setTagging(false)}
                      changed={trail.refresh}
                    />
                  </Show>
                </>
              )}
            </Show>
          </>
        )}
      </Show>
    </Show>
  );
}

function StatusPanel(props: { trail: TrailDetail; changed: () => void }) {
  const s = () => props.trail.status;
  const toggle = async () => {
    const logging = !s()?.logging;
    const done = await act(() => api.setTrailLogging(props.trail.name, logging), logging ? "Started logging" : "Stopped logging");
    if (done) props.changed();
  };
  return (
    <Panel title="Status" note="As GetTrailStatus answers.">
      <Show when={s()} fallback={<p class="subtle">You may not see the trail's status (cloudtrail:GetTrailStatus).</p>}>
        {(st) => (
          <>
            <div class="kv">
              <span class="subtle">Logging</span>
              <span>
                <StatusBadge status={st()} />{" "}
                <Show when={st().logging} fallback={<Show when={st().stopped}> since {date(st().stopped)}</Show>}>
                  <Show when={st().started}> since {date(st().started)}</Show>
                </Show>
              </span>
              <span class="subtle">Last delivered</span>
              <span>{st().delivered ? `${date(st().delivered)} (${ago(st().delivered)})` : "never"}</span>
              <span class="subtle">Last attempt</span>
              <span>
                {st().attempted ? date(st().attempted) : "never"}
                <Show when={st().attempted}> {st().attempt_succeeded ? <Badge tone="ok">succeeded</Badge> : <Badge tone="bad">failed</Badge>}</Show>
              </span>
              <Show when={st().error}>
                {(e) => (
                  <>
                    <span class="subtle">Error</span>
                    <span class="error-text">{e()}</span>
                  </>
                )}
              </Show>
            </div>
            <Show when={st().error}>
              <p class="subtle small">Failed deliveries are tried again every five minutes, for 30 days.</p>
            </Show>
            <div class="form-row" style={{ "margin-top": "12px" }}>
              <button class={st().logging ? "" : "primary"} onClick={toggle}>
                {st().logging ? "Stop logging" : "Start logging"}
              </button>
              <A href={eventsHref("ResourceName", props.trail.arn)}>Events about this trail</A>
            </div>
          </>
        )}
      </Show>
    </Panel>
  );
}

function SettingsPanel(props: { trail: TrailDetail; changed: () => void }) {
  const [bucket, setBucket] = createSignal(props.trail.bucket);
  const [prefix, setPrefix] = createSignal(props.trail.prefix ?? "");
  const [key, setKey] = createSignal(props.trail.kms_key_id ?? "");
  const [multiRegion, setMultiRegion] = createSignal(props.trail.multi_region);
  const [global, setGlobal] = createSignal(props.trail.include_global);
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const form = {
      bucket: bucket().trim(),
      prefix: prefix().trim(),
      kms_key_id: key().trim(),
      multi_region: multiRegion(),
      include_global: global(),
    };
    if (await act(() => api.updateTrail(props.trail.name, form), "Saved")) props.changed();
  };
  return (
    <Panel title="Settings" note="Where its log files go, and how they're encrypted (UpdateTrail).">
      <form class="rule" onSubmit={save}>
        <div class="form-row">
          <span class="label">Bucket</span>
          <input type="text" aria-label="Bucket" required value={bucket()} onInput={(e) => setBucket(e.currentTarget.value)} />
        </div>
        <div class="form-row">
          <span class="label">Key prefix</span>
          <input type="text" aria-label="Key prefix" placeholder="none" value={prefix()} onInput={(e) => setPrefix(e.currentTarget.value)} />
        </div>
        <div class="form-row">
          <span class="label">KMS key</span>
          <input type="text" aria-label="KMS key" placeholder="none: the bucket's default encryption" value={key()} onInput={(e) => setKey(e.currentTarget.value)} />
        </div>
        <div class="form-row">
          <label class="check label">
            <input type="checkbox" checked={global()} onChange={(e) => setGlobal(e.currentTarget.checked)} />
            Global services' events
          </label>
          <label class="check label">
            <input type="checkbox" checked={multiRegion()} onChange={(e) => setMultiRegion(e.currentTarget.checked)} />
            Multi-region
          </label>
        </div>
        <p class="subtle small">
          Files go to <span class="mono">{destination({ bucket: bucket(), prefix: prefix() })}</span>. A multi-region trail
          must have global services' events. Log file validation, SNS notifications and organization trails aren't
          there yet.
        </p>
        <div class="buttons">
          <button class="primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </Panel>
  );
}

/** Event selectors that are often wanted, as PutEventSelectors takes them. */
const PRESETS: [string, object][] = [
  ["Every management event", { EventSelectors: [{ ReadWriteType: "All", IncludeManagementEvents: true }] }],
  ["Writes only", { EventSelectors: [{ ReadWriteType: "WriteOnly", IncludeManagementEvents: true }] }],
  [
    "All but KMS's",
    {
      EventSelectors: [
        { ReadWriteType: "All", IncludeManagementEvents: true, ExcludeManagementEventSources: ["kms.amazonaws.com"] },
      ],
    },
  ],
  [
    "Failed calls only (advanced)",
    {
      AdvancedEventSelectors: [
        {
          Name: "Failed management events",
          FieldSelectors: [
            { Field: "eventCategory", Equals: ["Management"] },
            { Field: "errorCode", NotEquals: [""] },
          ],
        },
      ],
    },
  ],
];

function SelectorsPanel(props: { trail: TrailDetail; selectors: string; changed: () => void }) {
  const [text, setText] = createSignal(pretty(props.selectors));
  const save = async () => {
    if (await act(() => api.setTrailSelectors(props.trail.name, text()), "Saved the event selectors")) props.changed();
  };
  return (
    <Panel
      title="Event selectors"
      note={
        props.trail.custom_selectors
          ? "Which events it delivers (PutEventSelectors)."
          : "None set: it delivers every management event."
      }
    >
      <div class="form-row">
        <For each={PRESETS}>
          {([label, doc]) => (
            <button class="small" onClick={() => setText(JSON.stringify(doc, null, 2))}>
              {label}
            </button>
          )}
        </For>
      </div>
      <textarea class="policy" aria-label="Event selectors" value={text()} onInput={(e) => setText(e.currentTarget.value)} />
      <p class="subtle small">
        Basic selectors (<span class="mono">EventSelectors</span>: read, write or all management events, but those of
        the services they exclude) or advanced ones (<span class="mono">AdvancedEventSelectors</span>: conditions on{" "}
        <span class="mono">eventSource</span>, <span class="mono">eventName</span>, <span class="mono">readOnly</span>,{" "}
        <span class="mono">resources.ARN</span>, …). Every event Cairn records is a management event: data events'
        selectors are kept, but select nothing yet.
      </p>
      <div class="buttons">
        <button onClick={() => setText(pretty(props.selectors))}>Discard changes</button>
        <button class="primary" onClick={save}>
          Save event selectors
        </button>
      </div>
    </Panel>
  );
}
