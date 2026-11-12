// Dialogs for a bucket's or an object version's tags, and a bucket's CORS
// rules: what PutBucketTagging, PutObjectTagging and PutBucketCors set,
// checked by the server as S3 checks them.

import { For, Show, createSignal, onMount } from "solid-js";
import { type CorsConfiguration, api } from "../api";
import { act } from "./ui";

type Tag = { key: string; value: string };

/** Edits a tag set (`save` replaces it; an empty one removes them). */
export function TagsDialog(props: { title: string; tags: Tag[]; save: (tags: Tag[]) => Promise<unknown>; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  const [rows, setRows] = createSignal<Tag[]>(props.tags.length ? props.tags.map((t) => ({ ...t })) : [{ key: "", value: "" }]);
  onMount(() => dialog.showModal());
  const set = (i: number, field: "key" | "value", v: string) => setRows((r) => r.map((t, j) => (j === i ? { ...t, [field]: v } : t)));
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const tags = rows().filter((t) => t.key.trim() !== "");
    if (await act(() => props.save(tags), tags.length ? "Saved the tags" : "Removed the tags")) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{props.title}</h2>
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
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** A starting point for CORS rules: a site's pages may read and upload. */
const CORS_TEMPLATE: CorsConfiguration = {
  rules: [{ origins: ["https://app.example.com"], methods: ["GET", "PUT", "POST"], headers: ["*"], expose: ["ETag"], max_age: 3600 }],
};

/** Edits a bucket's CORS rules, as JSON (S3's CORSRule elements, by these
 * names: origins, methods, headers, expose, max_age, id). */
export function CorsDialog(props: { bucket: string; onClose: () => void }) {
  let dialog!: HTMLDialogElement;
  const [text, setText] = createSignal("");
  const [had, setHad] = createSignal(false);
  const [error, setError] = createSignal<string>();
  onMount(async () => {
    dialog.showModal();
    try {
      const c = await api.bucketCors(props.bucket);
      setHad(!!c.configuration);
      setText(JSON.stringify(c.configuration ?? CORS_TEMPLATE, null, 2));
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
    if (await act(() => api.putBucketCors(props.bucket, configuration), `Saved the CORS rules of ${props.bucket}`)) dialog.close();
  };
  const remove = async () => {
    if (!confirm(`Remove the CORS rules of ${props.bucket}? No other site's page may use it then.`)) return;
    if (await act(() => api.deleteBucketCors(props.bucket), `Removed the CORS rules of ${props.bucket}`)) dialog.close();
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          CORS of <span class="mono">{props.bucket}</span>
        </h2>
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
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Save
          </button>
        </div>
      </form>
    </dialog>
  );
}
