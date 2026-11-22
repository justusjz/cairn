// A bucket's pages besides its objects and the rules that have pages of
// their own (lifecycle, replication, notifications, inventory): who may
// access it, its tags, settings, CORS rules and website.

import { A, useParams } from "@solidjs/router";
import { For, Show, createResource, createSignal, onMount, type JSX } from "solid-js";
import { type BucketAccess, type PublicAccessBlock, api } from "../api";
import { BucketSettings } from "../components/BucketSettings";
import { PolicyDocumentEditor } from "../components/PolicyBuilder";
import { CorsEditor, TagsForm, WebsiteEditor } from "../components/Editors";
import { Badge, Loading, Table, toast } from "../components/ui";
import { pretty } from "../format";
import { bucketUrl } from "./Buckets";

/** A bucket page's heading and crumbs; `children` (keyed by the bucket, so
 * that going to another bucket's starts over) under them. */
function BucketPage(props: { title: string; crumb: string; children: (bucket: string) => JSX.Element }) {
  const params = useParams();
  const bucket = () => params.bucket ?? "";
  return (
    <>
      <h1>
        {props.title} <span class="mono">{bucket()}</span>
      </h1>
      <div class="crumbs">
        <A href="/buckets">Buckets</A>
        <span class="sep">/</span>
        <A href={bucketUrl(bucket())}>{bucket()}</A>
        <span class="sep">/</span>
        <span>{props.crumb}</span>
      </div>
      <Show when={bucket()} keyed>
        {(b) => props.children(b)}
      </Show>
    </>
  );
}

/** Who may access the bucket: its users, public access block and policy. */
export function BucketAccessPage() {
  return <BucketPage title="Access to" crumb="access">{(b) => <AccessEditor bucket={b} />}</BucketPage>;
}

/** The bucket's tags (PutBucketTagging). */
export function BucketTagsPage() {
  return (
    <BucketPage title="Tags of" crumb="tags">
      {(b) => {
        const [tags] = createResource(async () => (await api.buckets()).find((x) => x.name === b)?.tags ?? []);
        return (
          <Show when={tags()} fallback={<Loading error={tags.error?.message} />}>
            {(t) => (
              <div class="panel sheet">
                <TagsForm tags={t()} save={(tags) => api.setBucketTags(b, tags)} done={() => {}} />
              </div>
            )}
          </Show>
        );
      }}
    </BucketPage>
  );
}

/** The bucket's settings that S3 keeps as documents of their own. */
export function BucketSettingsPage() {
  return <BucketPage title="Settings of" crumb="settings">{(b) => <BucketSettings bucket={b} />}</BucketPage>;
}

/** The bucket's CORS rules. */
export function BucketCorsPage() {
  return <BucketPage title="CORS of" crumb="cors">{(b) => <CorsEditor bucket={b} />}</BucketPage>;
}

/** The bucket's website. */
export function BucketWebsitePage() {
  return <BucketPage title="Website of" crumb="website">{(b) => <WebsiteEditor bucket={b} />}</BucketPage>;
}

/** An example of a bucket's policy: anyone may read what's under
 * `public/`. Only ever a placeholder, or put in on request: a bucket without
 * a policy mustn't look like it has this one, nor get it by a stray Save. */
const POLICY_TEMPLATE = (bucket: string) => `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${bucket}/public/*"
    }
  ]
}`;

/** The public access block's flags, as the page shows them. */
const FLAGS: { key: keyof PublicAccessBlock; label: string; note: string }[] = [
  { key: "block_public_policy", label: "Block public policies", note: "A policy that makes the bucket public is refused." },
  {
    key: "restrict_public_buckets",
    label: "Restrict public buckets",
    note: "A public policy allows nothing to anyone outside the bucket's account, unsigned requests included; the account's users keep what it allows them.",
  },
  { key: "block_public_acls", label: "Block public ACLs", note: "Refuses ACLs that grant everyone, or any signed request, anything." },
  { key: "ignore_public_acls", label: "Ignore public ACLs", note: "Such grants allow nothing." },
];

/** A bucket's policy and public access block, to view and change. The
 * server checks the policy as S3 does, and says what's wrong. */
function AccessEditor(props: { bucket: string }) {
  const [access, setAccess] = createSignal<BucketAccess>();
  const [block, setBlock] = createSignal<PublicAccessBlock>({
    block_public_acls: false,
    ignore_public_acls: false,
    block_public_policy: false,
    restrict_public_buckets: false,
  });
  const [document, setDocument] = createSignal("");
  const [error, setError] = createSignal<string>();
  const load = async () => {
    try {
      const a = await api.bucketAccess(props.bucket);
      setAccess(a);
      if (a.public_access_block) setBlock({ ...a.public_access_block });
      setDocument(a.policy ? pretty(a.policy) : "");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  onMount(load);
  const run = async (fn: () => Promise<unknown>, done: string) => {
    setError(undefined);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(done);
    await load();
  };
  const saveBlock = () => run(() => api.putPublicAccessBlock(props.bucket, block()), `Saved the public access block of ${props.bucket}`);
  const removeBlock = () => {
    if (!confirm(`Remove the public access block of "${props.bucket}"? Only its account's will apply.`)) return;
    run(() => api.deletePublicAccessBlock(props.bucket), `Removed the public access block of ${props.bucket}`);
  };
  const savePolicy = () => run(() => api.putBucketPolicy(props.bucket, document()), `Saved the policy of ${props.bucket}`);
  const removePolicy = () => {
    if (!confirm(`Delete the policy of "${props.bucket}"?`)) return;
    run(() => api.deleteBucketPolicy(props.bucket), `Deleted the policy of ${props.bucket}`);
  };
  return (
    <div class="panel sheet">
      <Show when={access()} fallback={<Loading error={error()} />}>
        {(a) => (
          <>
            <h3>Users with access</h3>
            <p class="subtle small">
              The account's users whose own policies (attached and inline; see Users and Policies) allow them something
              on the whole bucket. Access only to a prefix, or under conditions, isn't shown; the bucket policy below
              may allow more, and its Deny statements win over all of it.
            </p>
            <Table count={a().users.length} empty="No one, by their own policies." columns={["User", "May"]}>
              <For each={a().users}>
                {(u) => (
                  <tr>
                    <td class="mono">{u.user}</td>
                    <td>
                      <For each={u.levels}>{(l) => <span class="chip">{l}</span>}</For>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
            <h3>Public access block</h3>
            <Show
              when={!a().public_access_block_hidden}
              fallback={<p class="subtle small">Your policies don't let you see the bucket's own block.</p>}
            >
              <p class="subtle small">
                <Show when={a().public_access_block} fallback="The bucket has no block of its own: only its account's applies.">
                  The bucket's own block. Its account's applies as well
                  {a().account_public_access_block?.block_public_policy || a().account_public_access_block?.restrict_public_buckets
                    ? " (it has some on)"
                    : " (it has none on)"}
                  .
                </Show>
              </p>
              <For each={FLAGS}>
                {(f) => (
                  <div>
                    <label class="check" title={f.note}>
                      <input
                        type="checkbox"
                        checked={block()[f.key]}
                        onChange={(e) => setBlock({ ...block(), [f.key]: e.currentTarget.checked })}
                      />
                      {f.label}
                    </label>{" "}
                    <span class="subtle small">{f.note}</span>
                  </div>
                )}
              </For>
              <div class="buttons">
                <Show when={a().public_access_block}>
                  <button type="button" class="danger" onClick={removeBlock}>
                    Remove block
                  </button>
                </Show>
                <button type="button" class="primary" onClick={saveBlock}>
                  Save block
                </button>
              </div>
            </Show>
            <h3>
              Bucket policy{" "}
              <Show when={a().public}>
                <Badge tone="bad">public</Badge>
              </Show>
            </h3>
            <p class="subtle small">
              IAM's policy language, as a bucket policy: each statement names its Principal (
              <span class="mono">"*"</span> is anyone, unsigned requests too; a user is{" "}
              <span class="mono">arn:aws:iam::ACCOUNT:user/NAME</span>); Resource is the bucket or its objects.
            </p>
            <Show when={!a().policy}>
              <p>
                <strong>The bucket has no policy.</strong>{" "}
                <span class="subtle small">Write one below to set it; the example (which makes public/ readable by anyone) isn't set.</span>
              </p>
            </Show>
            <PolicyDocumentEditor
              kind="bucket"
              label="Bucket policy"
              bucket={props.bucket}
              emptyIsNone
              placeholder={a().policy ? undefined : POLICY_TEMPLATE(props.bucket)}
              document={document()}
              setDocument={setDocument}
            />
            <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
            <div class="buttons">
              <Show when={a().policy}>
                <button type="button" class="danger" onClick={removePolicy}>
                  Delete policy
                </button>
              </Show>
              <Show when={!a().policy && !document().trim()}>
                <button type="button" onClick={() => setDocument(POLICY_TEMPLATE(props.bucket))}>
                  Use example
                </button>
              </Show>
              <button type="button" class="primary" disabled={!document().trim()} onClick={savePolicy}>
                Save policy
              </button>
            </div>
          </>
        )}
      </Show>
    </div>
  );
}

