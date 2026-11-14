// A policy document's editor: the JSON, and the bucket-access template
// (`src/templates.rs`, as the server writes it: what grants allow) adding a
// statement for a bucket, or the buckets a pattern names, at a level of
// access. Used for managed policies (the Policies page) and users' and
// roles' inline ones alike.

import { For, Show, createSignal } from "solid-js";
import { type Level, api } from "../api";

/** The levels of access to offer, as the bucket-access template's. */
export const LEVELS: { id: string; label: string; levels: Level[] }[] = [
  { id: "read", label: "Read", levels: ["read"] },
  { id: "read-write", label: "Read and write", levels: ["read", "write"] },
  { id: "read-write-delete", label: "Read, write and delete versions", levels: ["read", "write", "delete-version"] },
  { id: "manage", label: "Manage (configuration, policy, deleting it)", levels: ["manage"] },
  { id: "all", label: "Everything", levels: ["read", "write", "delete-version", "manage"] },
];

/** An empty identity policy. */
export const EMPTY = `{
  "Version": "2012-10-17",
  "Statement": []
}`;

/** `document` with a statement allowing `level` (a `LEVELS` ID) on
 * `buckets` added: the bucket-access template's. */
export async function withStatement(document: string, buckets: string, level: string): Promise<string> {
  const doc = JSON.parse(document.trim() || EMPTY);
  const statements = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
  const l = LEVELS.find((x) => x.id === level)!;
  const made = await api.previewTemplate({ template: "bucket-access", buckets, levels: l.levels });
  statements.push(...JSON.parse(made[0].document).Statement);
  doc.Version ??= "2012-10-17";
  doc.Statement = statements;
  return JSON.stringify(doc, null, 2);
}

/** The document's text, and the template above it. */
export function PolicyEditor(props: {
  document: string;
  setDocument: (d: string) => void;
  buckets: string[];
  readOnly?: boolean;
  disabled?: boolean;
}) {
  const [bucket, setBucket] = createSignal(props.buckets[0] ?? "");
  const [level, setLevel] = createSignal("read");
  const [error, setError] = createSignal<string>();
  const add = async () => {
    try {
      JSON.parse(props.document.trim() || EMPTY);
    } catch {
      setError("The document isn't valid JSON yet: fix it first, or clear it.");
      return;
    }
    try {
      props.setDocument(await withStatement(props.document, bucket().trim(), level()));
      setError(undefined);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <>
      <Show when={!props.readOnly}>
        <div class="form-row template">
          <span class="subtle small">Allow</span>
          <select aria-label="Level" value={level()} onChange={(e) => setLevel(e.currentTarget.value)}>
            <For each={LEVELS}>{(l) => <option value={l.id}>{l.label}</option>}</For>
          </select>
          <span class="subtle small">on bucket</span>
          <input
            type="text"
            list="policy-buckets"
            aria-label="Bucket"
            placeholder="bucket, or team-*"
            value={bucket()}
            onInput={(e) => setBucket(e.currentTarget.value)}
          />
          <datalist id="policy-buckets">
            <For each={props.buckets}>{(b) => <option value={b} />}</For>
          </datalist>
          <button type="button" class="small" disabled={!bucket().trim()} onClick={add}>
            Add statement
          </button>
        </div>
        <Show when={error()}>{(e) => <p class="error-text small">{e()}</p>}</Show>
      </Show>
      <textarea
        class="policy"
        aria-label="Policy document"
        spellcheck={false}
        readOnly={props.readOnly}
        disabled={props.disabled}
        value={props.document}
        onInput={(e) => props.setDocument(e.currentTarget.value)}
      />
      <p class="subtle small">
        IAM's policy language, as an identity policy: no Principal; Resource names buckets (
        <span class="mono">arn:aws:s3:::bucket</span>) and objects (<span class="mono">arn:aws:s3:::bucket/key</span>).
        The template (the bucket-access template's, what grants allow) adds a statement for a whole bucket, or the
        buckets a pattern names; narrow it to a prefix (
        <span class="mono">arn:aws:s3:::bucket/logs/*</span>) by hand.
      </p>
    </>
  );
}
