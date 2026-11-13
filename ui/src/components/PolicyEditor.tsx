// A policy document's editor: the JSON, and a template that writes the
// statement for a bucket (or a pattern of buckets) at a level of access,
// readably, as one would by hand. A bucket has at most one such statement:
// choosing another level for it changes that statement rather than adding a
// second. Used for managed policies (the Policies page) and users' inline
// ones alike.

import { For, Show, createMemo, createSignal } from "solid-js";

const READ = ["s3:Get*", "s3:List*"];
const WRITE = [
  ...READ,
  "s3:PutObject",
  "s3:PutObjectTagging",
  "s3:DeleteObject",
  "s3:DeleteObjectTagging",
  "s3:AbortMultipartUpload",
];

/** What each level allows, on a bucket and every object in it. None of them
 * allows anything of IAM's: users and their policies stay the admins'. */
export const LEVELS: { id: string; label: string; actions: string | string[] }[] = [
  { id: "read", label: "Read", actions: READ },
  { id: "read-write", label: "Read and write", actions: WRITE },
  {
    id: "share",
    label: "Read, write and share",
    actions: [...WRITE, "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"],
  },
  { id: "full", label: "Full, incl. creating it (s3:*)", actions: "s3:*" },
];

/** An empty identity policy. */
export const EMPTY = `{
  "Version": "2012-10-17",
  "Statement": []
}`;

type Statement = Record<string, unknown>;

function resources(bucket: string): string[] {
  return [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`];
}

function list(v: unknown): unknown[] {
  return Array.isArray(v) ? v : v === undefined ? [] : [v];
}

/** Whether `s` is the template's statement for `bucket`: an unconditional
 * Allow of actions on exactly the bucket and its objects. */
function isFor(s: Statement, bucket: string): boolean {
  if (s.Effect !== "Allow" || "Condition" in s || "NotAction" in s || "NotResource" in s) return false;
  const have = list(s.Resource);
  const want = resources(bucket);
  return have.length === want.length && want.every((r) => have.includes(r));
}

function parse(document: string): { doc: Record<string, unknown>; statements: Statement[] } {
  const doc = JSON.parse(document.trim() || EMPTY);
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new Error("not a policy");
  return { doc, statements: list(doc.Statement) as Statement[] };
}

/** The level `document` allows on `bucket` by the template's statement, if
 * it has one ("custom" if its actions are none of the levels'). */
export function levelOf(document: string, bucket: string): string | undefined {
  const s = parse(document).statements.find((s) => isFor(s, bucket));
  if (!s) return undefined;
  const actions = JSON.stringify(list(s.Action));
  return LEVELS.find((l) => JSON.stringify(list(l.actions)) === actions)?.id ?? "custom";
}

/** `document` allowing `level` on `bucket`: its statement for the bucket
 * changed to the level, or one added; `level` undefined removes it. Other
 * statements are kept as they are. */
export function withStatement(document: string, bucket: string, level: string | undefined): string {
  const { doc, statements } = parse(document);
  const l = LEVELS.find((x) => x.id === level);
  const at = statements.findIndex((s) => isFor(s, bucket));
  const kept = statements.filter((s, i) => i === at || !isFor(s, bucket));
  const i = kept.findIndex((s) => isFor(s, bucket));
  if (!l) {
    if (i >= 0) kept.splice(i, 1);
  } else if (i >= 0) {
    kept[i] = { ...kept[i], Action: l.actions };
  } else {
    kept.push({ Effect: "Allow", Action: l.actions, Resource: resources(bucket) });
  }
  doc.Version ??= "2012-10-17";
  doc.Statement = kept;
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
  // What the document allows on the bucket already, by the template.
  const current = createMemo(() => {
    const b = bucket().trim();
    if (!b) return undefined;
    try {
      return levelOf(props.document, b);
    } catch {
      return undefined;
    }
  });
  const apply = (l: string | undefined) => {
    try {
      props.setDocument(withStatement(props.document, bucket().trim(), l));
      setError(undefined);
    } catch {
      setError("The document isn't valid JSON yet: fix it first, or clear it.");
    }
  };
  const label = (id: string | undefined) =>
    id === "custom" ? "custom actions" : LEVELS.find((l) => l.id === id)?.label.toLowerCase();
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
            placeholder="bucket, or prefix-*"
            value={bucket()}
            onInput={(e) => setBucket(e.currentTarget.value)}
          />
          <datalist id="policy-buckets">
            <For each={props.buckets}>{(b) => <option value={b} />}</For>
          </datalist>
          <button
            type="button"
            class="small"
            disabled={!bucket().trim() || current() === level()}
            onClick={() => apply(level())}
          >
            {current() ? "Change statement" : "Add statement"}
          </button>
          <Show when={current()}>
            <button type="button" class="small" onClick={() => apply(undefined)}>
              Remove
            </button>
          </Show>
        </div>
        <Show when={current()}>
          <p class="subtle small">
            The document allows {label(current())} on {bucket().trim()} already; changing it replaces that statement.
          </p>
        </Show>
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
        The template writes one statement per bucket. A pattern (<span class="mono">team-*</span>) covers every bucket
        it matches, including ones made later. <em>Share</em> adds editing the bucket's policy, so its holder can give
        others access to that bucket, and only that one; <em>Full</em> adds creating and deleting buckets of the name
        or pattern, and their settings. None of them allows managing users or policies. Narrow a statement to a prefix
        (<span class="mono">arn:aws:s3:::bucket/logs/*</span>) by hand.
      </p>
    </>
  );
}
