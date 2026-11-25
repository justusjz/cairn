// Tags of a bucket, a topic or an object version, and a bucket's CORS rules
// and website: what PutBucketTagging, PutObjectTagging, PutBucketCors and
// PutBucketWebsite set, checked by the server as S3 checks them.

import { For, Index, Show, createMemo, createSignal, onMount } from "solid-js";
import { type CorsConfiguration, type RoutingRule, type WebsiteConfiguration, api } from "../api";
import { Chips, EditorTabs, editorMode } from "./PolicyBuilder";
import { Loading, act } from "./ui";

type Tag = { key: string; value: string };

/** Edits a tag set (`save` replaces it; an empty one removes them), in a
 * dialog. */
export function TagsDialog(props: { title: string; tags: Tag[]; save: (tags: Tag[]) => Promise<unknown>; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <h2>{props.title}</h2>
      <TagsForm
        tags={props.tags}
        save={props.save}
        done={() => {
          props.changed();
          dialog.close();
        }}
        cancel={() => dialog.close()}
      />
    </dialog>
  );
}

/** Edits a tag set: `done` once `save` took it, and a Cancel button if
 * there's `cancel`. */
export function TagsForm(props: { tags: Tag[]; save: (tags: Tag[]) => Promise<unknown>; done: () => void; cancel?: () => void }) {
  const [rows, setRows] = createSignal<Tag[]>(props.tags.length ? props.tags.map((t) => ({ ...t })) : [{ key: "", value: "" }]);
  const set = (i: number, field: "key" | "value", v: string) => setRows((r) => r.map((t, j) => (j === i ? { ...t, [field]: v } : t)));
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const tags = rows().filter((t) => t.key.trim() !== "");
    if (await act(() => props.save(tags), tags.length ? "Saved the tags" : "Removed the tags")) props.done();
  };
  return (
    <form onSubmit={save}>
      <p class="subtle small">Keys and values, as S3's tags: unique keys, at most 50 on a bucket and 10 on an object.</p>
      <For each={rows()}>
        {(t, i) => (
          <div class="form-row">
            <input type="text" placeholder="key" aria-label="Key" value={t.key} onInput={(e) => set(i(), "key", e.currentTarget.value)} />
            <input type="text" placeholder="value" aria-label="Value" value={t.value} onInput={(e) => set(i(), "value", e.currentTarget.value)} />
            <button type="button" class="small" onClick={() => setRows((r) => r.filter((_, j) => j !== i()))}>
              ×
            </button>
          </div>
        )}
      </For>
      <button type="button" class="small" onClick={() => setRows((r) => [...r, { key: "", value: "" }])}>
        Add a tag
      </button>
      <div class="buttons">
        <Show when={props.cancel}>
          {(cancel) => (
            <button type="button" onClick={() => cancel()()}>
              Cancel
            </button>
          )}
        </Show>
        <button class="primary" type="submit">
          Save
        </button>
      </div>
    </form>
  );
}

/** An example of CORS rules, shown while there are none: a site's pages
 * may read and upload. */
const CORS_EXAMPLE = `{
  "CORSRules": [
    {
      "AllowedOrigins": ["https://app.example.com"],
      "AllowedMethods": ["GET", "PUT", "POST"],
      "AllowedHeaders": ["*"],
      "ExposeHeaders": ["ETag"],
      "MaxAgeSeconds": 3600
    }
  ]
}`;

/** The methods a CORS rule may allow, as S3 names them. */
const CORS_METHODS = ["GET", "HEAD", "PUT", "POST", "DELETE"];

/** Headers a page commonly sends, and S3's it may want to read. */
const SENT_HEADERS = ["*", "content-type", "content-md5", "authorization", "x-amz-*", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"];
const EXPOSED_HEADERS = ["ETag", "x-amz-version-id", "x-amz-request-id", "x-amz-server-side-encryption", "Content-Length", "Content-Range", "Last-Modified"];

type CorsRule = CorsConfiguration["rules"][number];

// The JSON tabs hold rules as S3's console and API name them (`AllowedOrigins`,
// `KeyPrefixEquals`), so that what AWS's documentation shows can be pasted;
// the console's API, and what Cairn stores, names them its own way.

/** How a field of S3's JSON is read: its name in the console's API, and
 * what it holds (a number S3 writes as a string is `"code"`). */
type S3Field = [string, "string" | "strings" | "integer" | "code"];

/** `value`, an object of S3's JSON with `fields`, in the console API's
 * names; or why it isn't one. */
function fromS3(value: unknown, fields: Record<string, S3Field>, what: string): Record<string, unknown> | string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return `${what} isn't an object.`;
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(value)) {
    const field = fields[key];
    if (!field) return `${what} has ${key}, which S3 doesn't know here (it knows ${Object.keys(fields).join(", ")}).`;
    const [name, kind] = field;
    if (v === null || v === undefined) continue;
    if (kind === "string" && typeof v !== "string") return `${what}'s ${key} isn't a string.`;
    if (kind === "strings" && !(Array.isArray(v) && v.every((x) => typeof x === "string"))) return `${what}'s ${key} isn't a list of strings.`;
    if (kind === "integer" && !Number.isInteger(v)) return `${what}'s ${key} isn't a whole number.`;
    if (kind === "code") {
      const n = typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
      if (!Number.isInteger(n)) return `${what}'s ${key} isn't a status code.`;
      out[name] = n;
      continue;
    }
    out[name] = v;
  }
  return out;
}

/** `value`, in the console API's names, as S3's JSON with `fields` (in
 * their order): only what's set. */
function toS3(value: Record<string, unknown>, fields: Record<string, S3Field>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, [name, kind]] of Object.entries(fields)) {
    const v = value[name];
    if (v === undefined || v === null || (kind === "strings" && !(v as string[]).length)) continue;
    out[key] = kind === "code" ? String(v) : v;
  }
  return out;
}

/** The list `text` holds under `key`, as S3's API and the AWS CLI write
 * it (or a list itself, as the S3 console does); none if it's empty. */
function s3List(text: string, key: string, what: string): unknown[] | string {
  if (!text.trim()) return [];
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return `The ${what} aren't valid JSON: ${(e as Error).message}`;
  }
  if (Array.isArray(doc)) return doc;
  const inner = (doc as Record<string, unknown> | null)?.[key];
  if (Array.isArray(inner)) return inner;
  return `The ${what} aren't a list (or an object with ${key}).`;
}

const CORS_FIELDS: Record<string, S3Field> = {
  ID: ["id", "string"],
  AllowedOrigins: ["origins", "strings"],
  AllowedMethods: ["methods", "strings"],
  AllowedHeaders: ["headers", "strings"],
  ExposeHeaders: ["expose", "strings"],
  MaxAgeSeconds: ["max_age", "integer"],
};

/** The rules `text` holds (none if it's empty), or why they can't be read. */
function corsRules(text: string): { rules: CorsRule[] } | { error: string } {
  const list = s3List(text, "CORSRules", "CORS rules");
  if (typeof list === "string") return { error: list };
  const rules: CorsRule[] = [];
  for (const [i, r] of list.entries()) {
    const rule = fromS3(r, CORS_FIELDS, `Rule ${i + 1}`);
    if (typeof rule === "string") return { error: rule };
    rules.push({ ...rule, origins: (rule.origins as string[]) ?? [], methods: (rule.methods as string[]) ?? [] });
  }
  return { rules };
}

/** `rules` as the JSON the editor holds, S3's CORSConfiguration: only
 * the fields that are set, and nothing at all for no rules. */
function corsText(rules: CorsRule[]): string {
  if (!rules.length) return "";
  return JSON.stringify({ CORSRules: rules.map((r) => toS3({ ...r, id: r.id || undefined }, CORS_FIELDS)) }, null, 2);
}

/** Why `origin` matches no page's, or nothing. */
function originProblem(origin: string): string | undefined {
  if (origin === "*") return;
  if ((origin.match(/\*/g) ?? []).length > 1) return "An origin may have only one wildcard.";
  if (!origin.startsWith("*") && !/^[a-z][a-z0-9+.-]*:\/\//i.test(origin)) return "A page's origin is a scheme and a host (https://app.example.com): this matches none.";
  if (/^[a-z][a-z0-9+.-]*:\/\/[^/]*\/./i.test(origin) || origin.endsWith("/")) return "A page's origin has no path, not even a /: this matches none.";
}

/** A CORS rule, as a card: its origins, methods, headers and max age. */
function CorsRuleCard(props: { rule: CorsRule; n: number; set: (r: CorsRule) => void; remove: () => void; up?: () => void }) {
  const r = () => props.rule;
  const set = (changes: Partial<CorsRule>) => props.set({ ...r(), ...changes });
  const toggle = (m: string) => set({ methods: r().methods.includes(m) ? r().methods.filter((x) => x !== m) : CORS_METHODS.filter((x) => x === m || r().methods.includes(x)) });
  const summary = () => {
    const methods = r().methods.length ? r().methods.join(", ") : "nothing";
    const origins = r().origins.includes("*") ? "any site's pages" : r().origins.length === 1 ? r().origins[0] : `${r().origins.length} origins`;
    return `${methods}, from ${r().origins.length ? origins : "no site"}`;
  };
  const uploads = () => r().methods.some((m) => m === "PUT" || m === "POST") && !r().headers?.length;
  return (
    <section class="statement s3-rule">
      <header>
        <strong>Rule {props.n}</strong>
        <span class="subtle small">{summary()}</span>
        <span class="spacer" />
        <Show when={props.up}>
          {(up) => (
            <button type="button" class="small" title="Rules are tried in order: the first that matches a request answers it" onClick={() => up()()}>
              Move up
            </button>
          )}
        </Show>
        <button type="button" class="small danger" onClick={props.remove}>
          Remove
        </button>
      </header>
      <div class="rule">
        <div class="form-row">
          <span class="label mono">AllowedOrigins</span>
          <Chips
            values={r().origins}
            set={(origins) => set({ origins })}
            label="AllowedOrigins"
            placeholder="https://app.example.com, https://*.example.com, or *"
            split={/[\s,]+/}
            chip={(o) => {
              const problem = originProblem(o);
              return problem ? { bad: true, title: problem } : o === "*" ? { title: "Any site's pages" } : {};
            }}
          />
        </div>
        <div class="form-row">
          <span class="label mono">AllowedMethods</span>
          <For each={CORS_METHODS}>
            {(m) => (
              <button type="button" class="small mono" classList={{ active: r().methods.includes(m) }} aria-pressed={r().methods.includes(m)} onClick={() => toggle(m)}>
                {m}
              </button>
            )}
          </For>
        </div>
        <div class="form-row">
          <span class="label mono" title="The headers a page may send">AllowedHeaders</span>
          <Chips
            values={r().headers ?? []}
            set={(headers) => set({ headers })}
            label="AllowedHeaders"
            placeholder="content-type, x-amz-*, or *"
            suggestions={SENT_HEADERS}
            split={/[\s,]+/}
            chip={(h) => ((h.match(/\*/g) ?? []).length > 1 ? { bad: true, title: "A header may have only one wildcard." } : {})}
          />
        </div>
        <div class="form-row">
          <span class="label mono" title="The response headers a page may read">ExposeHeaders</span>
          <Chips
            values={r().expose ?? []}
            set={(expose) => set({ expose })}
            label="ExposeHeaders"
            placeholder="ETag, x-amz-version-id"
            suggestions={EXPOSED_HEADERS}
            split={/[\s,]+/}
            chip={(h) => (h.includes("*") ? { bad: true, title: "S3 takes no wildcards here: name each header." } : {})}
          />
        </div>
        <div class="form-row">
          <span class="label mono" title="How long a browser may keep a preflight's answer">MaxAgeSeconds</span>
          <input
            type="number"
            class="narrow"
            min="0"
            aria-label="MaxAgeSeconds"
            placeholder="seconds (optional)"
            value={r().max_age ?? ""}
            onInput={(e) => set({ max_age: e.currentTarget.value === "" ? undefined : Math.trunc(Number(e.currentTarget.value)) })}
          />
        </div>
        <div class="form-row">
          <span class="label mono">ID</span>
          <input type="text" class="narrow" aria-label="ID" placeholder="optional" value={r().id ?? ""} onInput={(e) => set({ id: e.currentTarget.value || undefined })} />
        </div>
        <Show when={!r().origins.length}>
          <p class="warn-note small">A rule needs an AllowedOrigin: the sites whose pages it lets in.</p>
        </Show>
        <Show when={!r().methods.length}>
          <p class="warn-note small">A rule needs an AllowedMethod: what those pages may do.</p>
        </Show>
        <Show when={uploads()}>
          <p class="warn-note small">
            Uploads from a page usually send a Content-Type, which a preflight asks for: allow <span class="mono">content-type</span> (or{" "}
            <span class="mono">*</span>) in AllowedHeaders.
          </p>
        </Show>
      </div>
    </section>
  );
}

/** Edits a bucket's CORS rules, in a visual builder or as JSON (S3's
 * console's: a list of rules with AllowedOrigins, AllowedMethods and so
 * on). The JSON is the truth; no rules is no configuration. */
export function CorsEditor(props: { bucket: string }) {
  const [text, setText] = createSignal("");
  const [had, setHad] = createSignal(false);
  const [loaded, setLoaded] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [mode, setMode] = editorMode();
  onMount(async () => {
    try {
      const c = await api.bucketCors(props.bucket);
      setHad(!!c.configuration);
      setText(c.configuration ? corsText(c.configuration.rules) : "");
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  });
  const parsed = createMemo(() => corsRules(text()));
  const rules = () => ("rules" in parsed() ? (parsed() as { rules: CorsRule[] }).rules : null);
  const setRules = (next: CorsRule[]) => setText(corsText(next));
  const remove = async () => {
    if (!confirm(`Remove the CORS rules of ${props.bucket}? No other site's page may use it then.`)) return;
    if (await act(() => api.deleteBucketCors(props.bucket), `Removed the CORS rules of ${props.bucket}`)) {
      setHad(false);
      setText("");
    }
  };
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    if (!text().trim()) {
      if (had()) await remove();
      return;
    }
    const read = corsRules(text());
    if ("error" in read) {
      setError(read.error);
      return;
    }
    setError(undefined);
    if (await act(() => api.putBucketCors(props.bucket, read), `Saved the CORS rules of ${props.bucket}`)) setHad(true);
  };
  const newRule = (): CorsRule => ({ origins: [], methods: ["GET", "HEAD"] });
  return (
    <Show when={loaded()} fallback={<Loading error={error()} />}>
      <form class="panel sheet" onSubmit={save}>
        <p class="subtle small">
          Which other sites' pages may use the bucket from a browser, and how: each rule's origins (one wildcard each, or{" "}
          <span class="mono">*</span> for any), the methods they may use, the headers they may send and read, and how long a browser
          may keep a preflight's answer. The first rule that matches a request answers it; up to 100.
        </p>
        <EditorTabs mode={mode()} setMode={setMode} />
        <Show
          when={mode() === "visual"}
          fallback={
            <textarea
              class="policy"
              aria-label="CORS rules"
              spellcheck={false}
              placeholder={CORS_EXAMPLE}
              value={text()}
              onInput={(e) => setText(e.currentTarget.value)}
            />
          }
        >
          <Show
            when={rules()}
            fallback={
              <p class="error-text">
                {"error" in parsed() ? (parsed() as { error: string }).error : ""}{" "}
                <button type="button" class="small" onClick={() => setMode("json")}>
                  Fix it in the JSON
                </button>
              </p>
            }
          >
            {(list) => (
              <div class="policy-builder">
                <Show when={!list().length}>
                  <p class="subtle">
                    No CORS rules{had() ? " left: saving removes them" : " yet"}, so no other site's page may use the bucket from a browser.
                  </p>
                </Show>
                <Index each={list()}>
                  {(rule, i) => (
                    <CorsRuleCard
                      rule={rule()}
                      n={i + 1}
                      set={(changed) => setRules(list().map((x, j) => (j === i ? changed : x)))}
                      remove={() => setRules(list().filter((_, j) => j !== i))}
                      up={i > 0 ? () => setRules(list().map((x, j) => (j === i - 1 ? list()[i] : j === i ? list()[i - 1] : x))) : undefined}
                    />
                  )}
                </Index>
                <div class="form-row">
                  <button type="button" class="small" disabled={list().length >= 100} onClick={() => setRules([...list(), newRule()])}>
                    Add rule
                  </button>
                </div>
              </div>
            )}
          </Show>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <Show when={had()}>
            <button type="button" class="danger" onClick={remove}>
              Remove
            </button>
          </Show>
          <button class="primary" type="submit" disabled={!had() && !text().trim()}>
            Save
          </button>
        </div>
      </form>
    </Show>
  );
}

/** An example routing rule, shown while there are none. */
const RULES_EXAMPLE = `{
  "RoutingRules": [
    {
      "Condition": { "KeyPrefixEquals": "docs/" },
      "Redirect": { "ReplaceKeyPrefixWith": "documents/" }
    }
  ]
}`;

/** The redirect codes a routing rule may use, and what each means. */
const REDIRECT_CODES: [number, string][] = [
  [301, "301 Moved Permanently (default)"],
  [302, "302 Found"],
  [303, "303 See Other"],
  [307, "307 Temporary Redirect"],
  [308, "308 Permanent Redirect"],
];

const CONDITION_FIELDS: Record<string, S3Field> = {
  KeyPrefixEquals: ["key_prefix_equals", "string"],
  HttpErrorCodeReturnedEquals: ["http_error_code_returned_equals", "code"],
};
const REDIRECT_FIELDS: Record<string, S3Field> = {
  Protocol: ["protocol", "string"],
  HostName: ["host_name", "string"],
  ReplaceKeyPrefixWith: ["replace_key_prefix_with", "string"],
  ReplaceKeyWith: ["replace_key_with", "string"],
  HttpRedirectCode: ["http_redirect_code", "code"],
};

/** The routing rules `text` holds (none if it's empty), or why they can't
 * be read. */
function routingRules(text: string): { rules: RoutingRule[] } | { error: string } {
  const list = s3List(text, "RoutingRules", "routing rules");
  if (typeof list === "string") return { error: list };
  const rules: RoutingRule[] = [];
  for (const [i, r] of list.entries()) {
    const what = `Rule ${i + 1}`;
    if (typeof r !== "object" || r === null || Array.isArray(r)) return { error: `${what} isn't an object.` };
    const other = Object.keys(r).find((k) => k !== "Condition" && k !== "Redirect");
    if (other) return { error: `${what} has ${other}, which S3 doesn't know here (it knows Condition, Redirect).` };
    const raw = r as { Condition?: unknown; Redirect?: unknown };
    let condition: Record<string, unknown> | string | undefined;
    if (raw.Condition !== undefined && raw.Condition !== null) {
      condition = fromS3(raw.Condition, CONDITION_FIELDS, `${what}'s Condition`);
      if (typeof condition === "string") return { error: condition };
    }
    if (raw.Redirect === undefined || raw.Redirect === null) return { error: `${what} has no Redirect.` };
    const redirect = fromS3(raw.Redirect, REDIRECT_FIELDS, `${what}'s Redirect`);
    if (typeof redirect === "string") return { error: redirect };
    rules.push({ condition, redirect } as RoutingRule);
  }
  return { rules };
}

/** Only the fields of `o` that are set. */
const setFields = <T extends object>(o: T): Partial<T> => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null)) as Partial<T>;

/** `rules` as the JSON the editor holds, S3's RoutingRules: only what's set (no
 * condition if it has nothing), and nothing at all for no rules. */
function routingText(rules: RoutingRule[]): string {
  if (!rules.length) return "";
  const written = rules.map((r) => {
    const condition = toS3(r.condition ?? {}, CONDITION_FIELDS);
    return { ...(Object.keys(condition).length ? { Condition: condition } : {}), Redirect: toS3(r.redirect, REDIRECT_FIELDS) };
  });
  return JSON.stringify({ RoutingRules: written }, null, 2);
}

/** A routing rule, as a card: the requests it redirects, and where to. */
function RoutingRuleCard(props: { rule: RoutingRule; n: number; set: (r: RoutingRule) => void; remove: () => void; up?: () => void }) {
  const c = () => props.rule.condition ?? {};
  const d = () => props.rule.redirect;
  const setCondition = (changes: Partial<NonNullable<RoutingRule["condition"]>>) => props.set({ ...props.rule, condition: { ...c(), ...changes } });
  const setRedirect = (changes: Partial<RoutingRule["redirect"]>) => props.set({ ...props.rule, redirect: { ...d(), ...changes } });
  const prefix = () => c().key_prefix_equals ?? "";
  const errorCode = () => c().http_error_code_returned_equals ?? undefined;
  const keyMode = () => (d().replace_key_with != null ? "key" : d().replace_key_prefix_with != null ? "prefix" : "keep");
  const setKeyMode = (mode: string) =>
    setRedirect({
      replace_key_with: mode === "key" ? (d().replace_key_with ?? d().replace_key_prefix_with ?? "") : undefined,
      replace_key_prefix_with: mode === "prefix" ? (d().replace_key_prefix_with ?? d().replace_key_with ?? "") : undefined,
    });
  const code = () => d().http_redirect_code ?? 301;
  const summary = () => {
    const from = `${prefix() ? `${prefix()}…` : "any key"}${errorCode() !== undefined ? `, once it gets a ${errorCode()}` : ""}`;
    const key =
      keyMode() === "key"
        ? d().replace_key_with || "/"
        : keyMode() === "prefix"
          ? `${d().replace_key_prefix_with ?? ""}…`
          : "the same key";
    const where = d().host_name || d().protocol ? `${d().protocol ? `${d().protocol}://` : ""}${d().host_name || "the same host"}, ` : "";
    return `${from} → ${where}${key}`;
  };
  const badError = () => errorCode() !== undefined && (errorCode()! < 400 || errorCode()! > 599);
  const badHost = () => !!d().host_name && !/^[A-Za-z0-9.\-_:[\]]+$/.test(d().host_name!);
  const empty = () => Object.keys(setFields(d())).length === 0;
  return (
    <section class="statement s3-rule">
      <header>
        <strong>Rule {props.n}</strong>
        <span class="subtle small">{summary()}</span>
        <span class="spacer" />
        <Show when={props.up}>
          {(up) => (
            <button type="button" class="small" title="Rules are tried in order: the first whose condition a request meets redirects it" onClick={() => up()()}>
              Move up
            </button>
          )}
        </Show>
        <button type="button" class="small danger" onClick={props.remove}>
          Remove
        </button>
      </header>
      <div class="rule">
        <span class="subtle small">Condition</span>
        <div class="form-row">
          <span class="label mono">KeyPrefixEquals</span>
          <input
            type="text"
            class="mono"
            aria-label="KeyPrefixEquals"
            placeholder="docs/ (optional)"
            value={prefix()}
            onInput={(e) => setCondition({ key_prefix_equals: e.currentTarget.value || undefined })}
          />
        </div>
        <div class="form-row">
          <span class="label mono" title="Only once a request would get this error">HttpErrorCodeReturnedEquals</span>
          <input
            type="number"
            class="narrow"
            classList={{ "bad-input": badError() }}
            min="400"
            max="599"
            aria-label="HttpErrorCodeReturnedEquals"
            placeholder="404 (optional)"
            value={errorCode() ?? ""}
            onInput={(e) => setCondition({ http_error_code_returned_equals: e.currentTarget.value === "" ? undefined : Math.trunc(Number(e.currentTarget.value)) })}
          />
        </div>
        <span class="subtle small">Redirect</span>
        <div class="form-row">
          <span class="label mono">Protocol</span>
          <select aria-label="Protocol" value={d().protocol ?? ""} onChange={(e) => setRedirect({ protocol: e.currentTarget.value || undefined })}>
            <option value="">None (the request's)</option>
            <option value="http">http</option>
            <option value="https">https</option>
          </select>
        </div>
        <div class="form-row">
          <span class="label mono">HostName</span>
          <input
            type="text"
            class="mono"
            classList={{ "bad-input": badHost() }}
            aria-label="HostName"
            placeholder="www.example.com (optional: the request's own)"
            value={d().host_name ?? ""}
            onInput={(e) => setRedirect({ host_name: e.currentTarget.value || undefined })}
          />
        </div>
        <div class="form-row">
          <select class="label mono" aria-label="What becomes of the key" value={keyMode()} onChange={(e) => setKeyMode(e.currentTarget.value)}>
            <option value="keep">Key unchanged</option>
            <option value="prefix">ReplaceKeyPrefixWith</option>
            <option value="key">ReplaceKeyWith</option>
          </select>
          <Show when={keyMode() !== "keep"}>
            <input
              type="text"
              class="mono"
              aria-label={keyMode() === "key" ? "ReplaceKeyWith" : "ReplaceKeyPrefixWith"}
              placeholder={keyMode() === "key" ? "error.html (empty: the root)" : prefix() ? "documents/ (empty: the prefix is removed)" : "documents/ (put before the key)"}
              value={(keyMode() === "key" ? d().replace_key_with : d().replace_key_prefix_with) ?? ""}
              onInput={(e) => setRedirect(keyMode() === "key" ? { replace_key_with: e.currentTarget.value } : { replace_key_prefix_with: e.currentTarget.value })}
            />
          </Show>
        </div>
        <div class="form-row">
          <span class="label mono">HttpRedirectCode</span>
          <select aria-label="HttpRedirectCode" value={String(code())} onChange={(e) => setRedirect({ http_redirect_code: Number(e.currentTarget.value) === 301 ? undefined : Number(e.currentTarget.value) })}>
            <Show when={!REDIRECT_CODES.some(([c]) => c === code())}>
              <option value={String(code())}>{code()}</option>
            </Show>
            <For each={REDIRECT_CODES}>{([c, label]) => <option value={String(c)}>{label}</option>}</For>
          </select>
        </div>
        <Show when={badError()}>
          <p class="warn-note small">The error a request gets is a 4XX or a 5XX.</p>
        </Show>
        <Show when={badHost()}>
          <p class="warn-note small">A host name alone, without a scheme or a path: www.example.com.</p>
        </Show>
        <Show when={d().http_redirect_code != null && (d().http_redirect_code! < 301 || d().http_redirect_code! > 399)}>
          <p class="warn-note small">A redirect's status is a 3XX, but not 300.</p>
        </Show>
        <Show when={empty()}>
          <p class="warn-note small">The rule redirects to the very same place: change the protocol, host, key or status.</p>
        </Show>
      </div>
    </section>
  );
}

/** A website's routing rules, in a visual builder or as their JSON. */
function RoutingRulesEditor(props: { text: string; setText: (t: string) => void }) {
  const [mode, setMode] = editorMode();
  const parsed = createMemo(() => routingRules(props.text));
  const rules = () => ("rules" in parsed() ? (parsed() as { rules: RoutingRule[] }).rules : null);
  const setRules = (next: RoutingRule[]) => props.setText(routingText(next));
  return (
    <div class="field">
      Routing rules (optional)
      <EditorTabs mode={mode()} setMode={setMode} />
      <Show
        when={mode() === "visual"}
        fallback={
          <textarea class="policy" aria-label="Routing rules" spellcheck={false} placeholder={RULES_EXAMPLE} value={props.text} onInput={(e) => props.setText(e.currentTarget.value)} />
        }
      >
        <Show
          when={rules()}
          fallback={
            <p class="error-text">
              {"error" in parsed() ? (parsed() as { error: string }).error : ""}{" "}
              <button type="button" class="small" onClick={() => setMode("json")}>
                Fix it in the JSON
              </button>
            </p>
          }
        >
          {(list) => (
            <div class="policy-builder">
              <Show when={!list().length}>
                <p class="subtle small">No routing rules: every request is answered from the bucket.</p>
              </Show>
              <Index each={list()}>
                {(rule, i) => (
                  <RoutingRuleCard
                    rule={rule()}
                    n={i + 1}
                    set={(changed) => setRules(list().map((x, j) => (j === i ? changed : x)))}
                    remove={() => setRules(list().filter((_, j) => j !== i))}
                    up={i > 0 ? () => setRules(list().map((x, j) => (j === i - 1 ? list()[i] : j === i ? list()[i - 1] : x))) : undefined}
                  />
                )}
              </Index>
              <div class="form-row">
                <button type="button" class="small" disabled={list().length >= 50} onClick={() => setRules([...list(), { redirect: {} }])}>
                  Add rule
                </button>
              </div>
            </div>
          )}
        </Show>
      </Show>
    </div>
  );
}

/** Edits a bucket's website: its index and error documents and routing
 * rules (in a visual builder or as S3's JSON: a list of rules with a
 * Condition and a Redirect), or a host every request is redirected to. */
export function WebsiteEditor(props: { bucket: string }) {
  const [loaded, setLoaded] = createSignal(false);
  const [had, setHad] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [mode, setMode] = createSignal<"serve" | "redirect">("serve");
  const [index, setIndex] = createSignal("index.html");
  const [errorDocument, setErrorDocument] = createSignal("");
  const [rules, setRules] = createSignal("");
  const [host, setHost] = createSignal("");
  const [protocol, setProtocol] = createSignal("");
  onMount(async () => {
    try {
      const c = (await api.bucketWebsite(props.bucket)).configuration;
      setLoaded(true);
      if (!c) return;
      setHad(true);
      if (c.redirect_all_requests_to) {
        setMode("redirect");
        setHost(c.redirect_all_requests_to.host_name);
        setProtocol(c.redirect_all_requests_to.protocol ?? "");
      } else {
        setIndex(c.index_document ?? "");
        setErrorDocument(c.error_document ?? "");
        if (c.routing_rules?.length) setRules(routingText(c.routing_rules));
      }
    } catch (e) {
      setError((e as Error).message);
    }
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    setError(undefined);
    let configuration: WebsiteConfiguration;
    if (mode() === "redirect") {
      configuration = { redirect_all_requests_to: { host_name: host().trim(), protocol: protocol() || undefined } };
    } else {
      const read = routingRules(rules());
      if ("error" in read) {
        setError(read.error);
        return;
      }
      const routing_rules = read.rules;
      configuration = { index_document: index(), error_document: errorDocument() || undefined, routing_rules };
    }
    if (await act(() => api.putBucketWebsite(props.bucket, configuration), `Saved the website of ${props.bucket}`)) setHad(true);
  };
  const remove = async () => {
    if (!confirm(`Turn off the website of ${props.bucket}? Its website endpoint serves nothing then.`)) return;
    if (await act(() => api.deleteBucketWebsite(props.bucket), `Turned off the website of ${props.bucket}`)) {
      setHad(false);
      setMode("serve");
      setIndex("index.html");
      setErrorDocument("");
      setRules("");
      setHost("");
      setProtocol("");
    }
  };
  return (
    <Show when={loaded()} fallback={<Loading error={error()} />}>
      <form class="panel sheet" onSubmit={save}>
        <p class="subtle small">
          Served at the bucket's website endpoint, to anyone: only what the bucket's policy lets anyone read (
          <span class="mono">s3:GetObject</span> for <span class="mono">"*"</span>) is served, and a missing page is a 403 unless anyone may
          list the bucket too.
        </p>
        <label class="field">
          The website
          <select value={mode()} onChange={(e) => setMode(e.currentTarget.value as "serve" | "redirect")}>
            <option value="serve">Serves the bucket's objects</option>
            <option value="redirect">Redirects every request to another host</option>
          </select>
        </label>
        <Show
          when={mode() === "serve"}
          fallback={
            <>
              <label class="field">
                Host name
                <input type="text" required placeholder="www.example.com" value={host()} onInput={(e) => setHost(e.currentTarget.value)} />
              </label>
              <label class="field">
                Protocol
                <select value={protocol()} onChange={(e) => setProtocol(e.currentTarget.value)}>
                  <option value="">The request's</option>
                  <option value="http">http</option>
                  <option value="https">https</option>
                </select>
              </label>
            </>
          }
        >
          <label class="field">
            Index document
            <input type="text" required value={index()} onInput={(e) => setIndex(e.currentTarget.value)} />
          </label>
          <p class="subtle small">Served for the root and for any key ending in /, appended to it: docs/ serves docs/index.html.</p>
          <label class="field">
            Error document (optional)
            <input type="text" placeholder="error.html" value={errorDocument()} onInput={(e) => setErrorDocument(e.currentTarget.value)} />
          </label>
          <RoutingRulesEditor text={rules()} setText={setRules} />
          <p class="subtle small">
            The first rule whose condition a request meets redirects it: by its key's prefix, or by the error it got (a 4XX or 5XX status). Up to 50.
          </p>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <Show when={had()}>
            <button type="button" class="danger" onClick={remove}>
              Turn off
            </button>
          </Show>
          <button class="primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </Show>
  );
}
