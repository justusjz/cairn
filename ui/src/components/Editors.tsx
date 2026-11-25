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
const CORS_EXAMPLE = JSON.stringify(
  { rules: [{ origins: ["https://app.example.com"], methods: ["GET", "PUT", "POST"], headers: ["*"], expose: ["ETag"], max_age: 3600 }] },
  null,
  2,
);

/** The methods a CORS rule may allow, as S3 names them. */
const CORS_METHODS = ["GET", "HEAD", "PUT", "POST", "DELETE"];

/** Headers a page commonly sends, and S3's it may want to read. */
const SENT_HEADERS = ["*", "content-type", "content-md5", "authorization", "x-amz-*", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"];
const EXPOSED_HEADERS = ["ETag", "x-amz-version-id", "x-amz-request-id", "x-amz-server-side-encryption", "Content-Length", "Content-Range", "Last-Modified"];

type CorsRule = CorsConfiguration["rules"][number];

/** The rules `text` holds (none if it's empty), or why the builder can't
 * show them. */
function corsRules(text: string): { rules: CorsRule[] } | { error: string } {
  if (!text.trim()) return { rules: [] };
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { error: `The rules aren't valid JSON: ${(e as Error).message}` };
  }
  const rules = (doc as { rules?: unknown })?.rules;
  if (typeof doc !== "object" || doc === null || Array.isArray(doc) || !Array.isArray(rules)) return { error: "The JSON isn't an object with a list of rules." };
  const strings = (v: unknown) => v === undefined || (Array.isArray(v) && v.every((x) => typeof x === "string"));
  for (const [i, r] of rules.entries()) {
    const ok =
      typeof r === "object" &&
      r !== null &&
      Object.keys(r).every((k) => ["id", "origins", "methods", "headers", "expose", "max_age"].includes(k)) &&
      (r.id === undefined || r.id === null || typeof r.id === "string") &&
      strings(r.origins) &&
      strings(r.methods) &&
      strings(r.headers) &&
      strings(r.expose) &&
      (r.max_age === undefined || r.max_age === null || Number.isInteger(r.max_age));
    if (!ok) return { error: `Rule ${i + 1} has a field the builder doesn't know, or a value of an odd shape.` };
  }
  return { rules: rules.map((r) => ({ ...r, origins: r.origins ?? [], methods: r.methods ?? [] })) };
}

/** `rules` as the JSON the editor holds: only the fields that are set, and
 * nothing at all for no rules. */
function corsText(rules: CorsRule[]): string {
  if (!rules.length) return "";
  const written = rules.map((r) => ({
    ...(r.id ? { id: r.id } : {}),
    origins: r.origins,
    methods: r.methods,
    ...(r.headers?.length ? { headers: r.headers } : {}),
    ...(r.expose?.length ? { expose: r.expose } : {}),
    ...(r.max_age !== undefined && r.max_age !== null ? { max_age: r.max_age } : {}),
  }));
  return JSON.stringify({ rules: written }, null, 2);
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
    <section class="statement">
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
          <span class="label">Origins</span>
          <Chips
            values={r().origins}
            set={(origins) => set({ origins })}
            label="Origins"
            placeholder="https://app.example.com, https://*.example.com, or *"
            split={/[\s,]+/}
            chip={(o) => {
              const problem = originProblem(o);
              return problem ? { bad: true, title: problem } : o === "*" ? { title: "Any site's pages" } : {};
            }}
          />
        </div>
        <div class="form-row">
          <span class="label">Methods</span>
          <For each={CORS_METHODS}>
            {(m) => (
              <button type="button" class="small mono" classList={{ active: r().methods.includes(m) }} aria-pressed={r().methods.includes(m)} onClick={() => toggle(m)}>
                {m}
              </button>
            )}
          </For>
        </div>
        <div class="form-row">
          <span class="label">Headers sent</span>
          <Chips
            values={r().headers ?? []}
            set={(headers) => set({ headers })}
            label="Headers a page may send"
            placeholder="content-type, x-amz-*, or *"
            suggestions={SENT_HEADERS}
            split={/[\s,]+/}
            chip={(h) => ((h.match(/\*/g) ?? []).length > 1 ? { bad: true, title: "A header may have only one wildcard." } : {})}
          />
        </div>
        <div class="form-row">
          <span class="label">Headers read</span>
          <Chips
            values={r().expose ?? []}
            set={(expose) => set({ expose })}
            label="Headers a page may read"
            placeholder="ETag, x-amz-version-id"
            suggestions={EXPOSED_HEADERS}
            split={/[\s,]+/}
            chip={(h) => (h.includes("*") ? { bad: true, title: "S3 takes no wildcards here: name each header." } : {})}
          />
        </div>
        <div class="form-row">
          <span class="label">Preflight kept</span>
          <input
            type="number"
            class="narrow"
            min="0"
            aria-label="Max age in seconds"
            placeholder="seconds (optional)"
            value={r().max_age ?? ""}
            onInput={(e) => set({ max_age: e.currentTarget.value === "" ? undefined : Math.trunc(Number(e.currentTarget.value)) })}
          />
          <input type="text" class="narrow" aria-label="Rule ID" placeholder="ID (optional)" value={r().id ?? ""} onInput={(e) => set({ id: e.currentTarget.value || undefined })} />
        </div>
        <Show when={!r().origins.length}>
          <p class="warn-note small">A rule needs an origin: the sites whose pages it lets in.</p>
        </Show>
        <Show when={!r().methods.length}>
          <p class="warn-note small">A rule needs a method: what those pages may do.</p>
        </Show>
        <Show when={uploads()}>
          <p class="warn-note small">
            Uploads from a page usually send a Content-Type, which a preflight asks for: allow <span class="mono">content-type</span> (or{" "}
            <span class="mono">*</span>) among the headers sent.
          </p>
        </Show>
      </div>
    </section>
  );
}

/** Edits a bucket's CORS rules, in a visual builder or as JSON (S3's
 * CORSRule elements, by these names: origins, methods, headers, expose,
 * max_age, id). The JSON is the truth; no rules is no configuration. */
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
    let configuration: CorsConfiguration;
    try {
      configuration = JSON.parse(text());
    } catch (e) {
      setError(`not JSON: ${(e as Error).message}`);
      return;
    }
    setError(undefined);
    if (await act(() => api.putBucketCors(props.bucket, configuration), `Saved the CORS rules of ${props.bucket}`)) setHad(true);
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
const RULES_EXAMPLE = `[
  {
    "condition": { "key_prefix_equals": "docs/" },
    "redirect": { "replace_key_prefix_with": "documents/" }
  }
]`;

/** Edits a bucket's website: its index and error documents and routing
 * rules (as JSON, S3's RoutingRule elements by these names: condition
 * with key_prefix_equals and http_error_code_returned_equals, redirect
 * with host_name, protocol, http_redirect_code, replace_key_prefix_with
 * and replace_key_with), or a host every request is redirected to. */
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
        if (c.routing_rules?.length) setRules(JSON.stringify(c.routing_rules, null, 2));
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
      let routing_rules: RoutingRule[] = [];
      if (rules().trim()) {
        try {
          routing_rules = JSON.parse(rules());
        } catch (e) {
          setError(`The routing rules aren't JSON: ${(e as Error).message}`);
          return;
        }
      }
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
          <label class="field">
            Routing rules (optional, JSON)
            <textarea class="policy" aria-label="Routing rules" spellcheck={false} placeholder={RULES_EXAMPLE} value={rules()} onInput={(e) => setRules(e.currentTarget.value)} />
          </label>
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
