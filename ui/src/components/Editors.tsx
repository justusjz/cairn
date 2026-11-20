// Tags of a bucket, a topic or an object version, and a bucket's CORS rules
// and website: what PutBucketTagging, PutObjectTagging, PutBucketCors and
// PutBucketWebsite set, checked by the server as S3 checks them.

import { For, Show, createSignal, onMount } from "solid-js";
import { type CorsConfiguration, type RoutingRule, type WebsiteConfiguration, api } from "../api";
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

/** A starting point for CORS rules: a site's pages may read and upload. */
const CORS_TEMPLATE: CorsConfiguration = {
  rules: [{ origins: ["https://app.example.com"], methods: ["GET", "PUT", "POST"], headers: ["*"], expose: ["ETag"], max_age: 3600 }],
};

/** Edits a bucket's CORS rules, as JSON (S3's CORSRule elements, by these
 * names: origins, methods, headers, expose, max_age, id). */
export function CorsEditor(props: { bucket: string }) {
  const [text, setText] = createSignal("");
  const [had, setHad] = createSignal(false);
  const [loaded, setLoaded] = createSignal(false);
  const [error, setError] = createSignal<string>();
  onMount(async () => {
    try {
      const c = await api.bucketCors(props.bucket);
      setHad(!!c.configuration);
      setText(JSON.stringify(c.configuration ?? CORS_TEMPLATE, null, 2));
      setLoaded(true);
    } catch (e) {
      setError((e as Error).message);
    }
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
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
  const remove = async () => {
    if (!confirm(`Remove the CORS rules of ${props.bucket}? No other site's page may use it then.`)) return;
    if (await act(() => api.deleteBucketCors(props.bucket), `Removed the CORS rules of ${props.bucket}`)) {
      setHad(false);
      setText(JSON.stringify(CORS_TEMPLATE, null, 2));
    }
  };
  return (
    <Show when={loaded()} fallback={<Loading error={error()} />}>
      <form class="panel sheet" onSubmit={save}>
        <p class="subtle small">
          Which other sites' pages may use the bucket from a browser, and how: each rule's origins (wildcards allowed),
          methods (GET, PUT, POST, DELETE, HEAD), the headers they may send and read, and how long a preflight's answer
          is kept.
        </p>
        <textarea class="policy" aria-label="CORS rules" spellcheck={false} value={text()} onInput={(e) => setText(e.currentTarget.value)} />
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <Show when={had()}>
            <button type="button" class="danger" onClick={remove}>
              Remove
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
