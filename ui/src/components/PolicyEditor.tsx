// A policy document's editor: the JSON, and a template that writes the
// statements for a bucket at a level of access, readably, as one would by
// hand. Used for managed policies (the Policies page) and users' inline
// ones alike.

import { For, Show, createSignal } from "solid-js";

/** What each level allows, on a bucket and every object in it. */
export const LEVELS: { id: string; label: string; actions: string | string[] }[] = [
  { id: "read", label: "Read", actions: ["s3:Get*", "s3:List*"] },
  {
    id: "read-write",
    label: "Read and write",
    actions: [
      "s3:Get*",
      "s3:List*",
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:DeleteObject",
      "s3:DeleteObjectTagging",
      "s3:AbortMultipartUpload",
    ],
  },
  { id: "full", label: "Full (s3:*)", actions: "s3:*" },
];

/** An empty identity policy. */
export const EMPTY = `{
  "Version": "2012-10-17",
  "Statement": []
}`;

/** `document` with a statement allowing `level` on `bucket` added. */
export function withStatement(document: string, bucket: string, level: string): string {
  const doc = JSON.parse(document.trim() || EMPTY);
  const statements = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
  const l = LEVELS.find((x) => x.id === level)!;
  statements.push({
    Effect: "Allow",
    Action: l.actions,
    Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
  });
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
  const add = () => {
    try {
      props.setDocument(withStatement(props.document, bucket().trim(), level()));
      setError(undefined);
    } catch {
      setError("The document isn't valid JSON yet: fix it first, or clear it.");
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
            placeholder="bucket"
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
        The template adds a statement for a whole bucket; narrow it to a prefix (
        <span class="mono">arn:aws:s3:::bucket/logs/*</span>) by hand.
      </p>
    </>
  );
}
