// An account's managed policies (see `src/managed.rs`): Cairn's, which have
// AWS's names and say what AWS's do, and the account's own, which are
// attached to users, roles and groups on their pages. The list, a policy's
// own page (its document, and who has it), making, changing (a new version)
// and deleting (once nothing has it attached) the account's own.

import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { For, Show, createResource, createSignal, onMount } from "solid-js";
import { type ManagedPolicy, type Tag, api } from "../api";
import { Chip, DetailHead, Gone, TagChips, TagRows, cleanTags, groupHref, policyHref, roleHref, userHref } from "../components/Iam";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { EMPTY, PolicyEditor } from "../components/PolicyEditor";
import { ago, pretty } from "../format";

/** Whether anyone has the policy: attached, or as a boundary. */
const used = (p: ManagedPolicy) =>
  p.users.length + p.bounds.length + p.roles.length + p.role_bounds.length + p.groups.length > 0;

export default function Policies() {
  const data = poll(() => Promise.all([api.policies(), api.buckets()]), 10000);
  const [creating, setCreating] = createSignal(false);
  const buckets = () => (data.data()?.[1] ?? []).map((b) => b.name);
  return (
    <>
      <div class="page-head">
        <h1>Policies</h1>
        <div class="buttons">
          <button class="primary" onClick={() => setCreating(true)}>
            New policy
          </button>
        </div>
      </div>
      <p class="subtle small">
        Managed policies are documents of their own, attached to any number of users, groups and roles: what a user, or a
        role's session, may do is what its attached and inline policies (and a user's groups') allow, and its buckets'
        policies, where they name it; a Deny wins over any Allow. Cairn's own have AWS's names and say what AWS's do, so
        policies and tools written for AWS work as they are.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Panel>
            <Table count={d()[0].length} columns={["Name", "Description", "Attached to", "Version"]}>
              <For each={d()[0]}>
                {(p) => (
                  <tr>
                    <td>
                      <A class="mono" href={policyHref(p.arn)}>
                        {p.name}
                      </A>{" "}
                      <Show when={p.aws}>
                        <Badge>Cairn's (AWS)</Badge>
                      </Show>
                      <Show when={p.path !== "/"}>
                        <div class="subtle small" title={p.arn}>
                          path {p.path}
                        </div>
                      </Show>
                    </td>
                    <td class="small">{p.description || <span class="subtle">–</span>}</td>
                    <td>
                      <UsedBy policy={p} />
                    </td>
                    <td class="small">
                      v{p.version}
                      <Show when={p.updated_at}>{(t) => <div class="subtle">{ago(t())}</div>}</Show>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={creating()}>
        <ManagedPolicyDialog policies={data.data()?.[0] ?? []} buckets={buckets()} onClose={() => setCreating(false)} changed={data.refresh} />
      </Show>
    </>
  );
}

/** Who has a policy, as links: attached to users, groups and roles, and as
 * their permissions boundary. */
function UsedBy(props: { policy: ManagedPolicy }) {
  const p = () => props.policy;
  return (
    <>
      <Show when={!used(p())}>
        <span class="subtle">no one</span>
      </Show>
      <For each={p().users}>{(u) => <Chip href={userHref(u)}>{u}</Chip>}</For>
      <For each={p().groups}>{(g) => <Chip href={groupHref(g)} title="A group: its members have it">group {g}</Chip>}</For>
      <For each={p().roles}>{(r) => <Chip href={roleHref(r)}>role {r}</Chip>}</For>
      <Show when={p().bounds.length || p().role_bounds.length}>
        <div class="small" title="Users and roles whose permissions boundary it is: it caps what their policies allow">
          boundary of <For each={p().bounds}>{(u) => <Chip href={userHref(u)}>{u}</Chip>}</For>
          <For each={p().role_bounds}>{(r) => <Chip href={roleHref(r)}>role {r}</Chip>}</For>
        </div>
      </Show>
    </>
  );
}

// ─── A policy's page ─────────────────────────────────────────────────────────

export function PolicyPage() {
  const params = useParams();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const name = () => params.name!;
  const aws = () => search.aws !== undefined;
  const data = poll(() => Promise.all([api.policies(), api.buckets()]), 10000);
  const policy = () => data.data()?.[0].find((p) => p.name === name() && p.aws === aws());
  const [editing, setEditing] = createSignal(false);
  const blocker = () => {
    const p = policy();
    if (!p || !used(p)) return "";
    return p.users.length || p.roles.length || p.groups.length
      ? "Detach it from its users, roles and groups first"
      : "It's a permissions boundary: take it off its users and roles first";
  };
  const remove = async () => {
    if (!confirm(`Delete policy "${name()}"?`)) return;
    if (await act(() => api.deleteManagedPolicy(name()), `Deleted ${name()}`)) navigate("/policies");
  };
  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      <Show when={policy()} fallback={<Gone kind="Policies" href="/policies" name={name()} />}>
        {(p) => (
          <>
            <DetailHead kind="Policies" href="/policies" name={p().name}>
              <Show when={!p().aws}>
                <button onClick={() => setEditing(true)}>Edit…</button>
                <button class="danger" disabled={!!blocker()} title={blocker()} onClick={remove}>
                  Delete
                </button>
              </Show>
            </DetailHead>
            <Panel title="Summary">
              <dl class="kv">
                <dt>ARN</dt>
                <dd class="mono">{p().arn}</dd>
                <dt>Description</dt>
                <dd>{p().description || <span class="subtle">none</span>}</dd>
                <Show when={!p().aws}>
                  <dt>Path</dt>
                  <dd class="mono">{p().path}</dd>
                </Show>
                <dt>Version</dt>
                <dd>
                  v{p().version}
                  <Show when={p().updated_at}>{(t) => <span class="subtle"> · {ago(t())}</span>}</Show>
                </dd>
                <Show when={!p().aws}>
                  <dt>Tags</dt>
                  <dd>
                    <TagChips tags={p().tags} title="A tag (aws:ResourceTag in IAM actions on the policy)" />
                  </dd>
                </Show>
              </dl>
              <Show when={p().aws}>
                <p class="subtle small">Cairn's policies are AWS's, and can't be changed: make one of your own instead.</p>
              </Show>
            </Panel>
            <Panel title="What it allows">
              <div class="pem">{pretty(p().document)}</div>
            </Panel>
            <Panel title="Who has it">
              <UsedBy policy={p()} />
            </Panel>
            <Show when={editing()}>
              <ManagedPolicyDialog
                policy={p()}
                policies={data.data()?.[0] ?? []}
                buckets={(data.data()?.[1] ?? []).map((b) => b.name)}
                onClose={() => setEditing(false)}
                changed={data.refresh}
              />
            </Show>
          </>
        )}
      </Show>
    </Show>
  );
}

/** A managed policy to view (Cairn's), edit, or make (`policy` not given). */
function ManagedPolicyDialog(props: {
  policy?: ManagedPolicy;
  policies: ManagedPolicy[];
  buckets: string[];
  onClose: () => void;
  changed: () => void;
}) {
  const navigate = useNavigate();
  let dialog!: HTMLDialogElement;
  const p = props.policy;
  const [name, setName] = createSignal(p?.name ?? "");
  const [description, setDescription] = createSignal(p?.description ?? "");
  const [document, setDocument] = createSignal(p ? pretty(p.document) : EMPTY);
  const [error, setError] = createSignal<string>();
  const [path, setPath] = createSignal("");
  const [tags, setTags] = createSignal<Tag[]>((p?.tags ?? []).map((t) => ({ ...t })));
  const [versions, { refetch: refetchVersions }] = createResource(
    () => (p && !p.aws ? p.name : undefined),
    (name) => api.policyVersions(name),
  );
  const makeDefault = async (v: number) => {
    if (await act(() => api.setDefaultVersion(p!.name, v), `v${v} of ${p!.name} decides now`)) {
      refetchVersions();
      props.changed();
    }
  };
  const deleteVersion = async (v: number) => {
    if (!confirm(`Delete v${v} of "${p!.name}"?`)) return;
    if (await act(() => api.deletePolicyVersion(p!.name, v), `Deleted v${v}`)) refetchVersions();
  };
  const wantedTags = () => cleanTags(tags());
  onMount(() => dialog.showModal());
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      if (p) {
        const change: { document?: string; description?: string } = {};
        if (document() !== pretty(p.document)) change.document = document();
        if (description() !== p.description) change.description = description();
        if (change.document !== undefined || change.description !== undefined) await api.updatePolicy(p.name, change);
        if (JSON.stringify(wantedTags()) !== JSON.stringify(p.tags)) await api.setPolicyTags(p.name, wantedTags());
      } else {
        await api.createPolicy(name().trim(), document(), description(), path().trim(), wantedTags());
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved ${p?.name ?? name().trim()}`);
    props.changed();
    dialog.close();
    if (!p) navigate(policyHref(`/${name().trim()}`));
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          <Show when={p} fallback="New policy">
            {(p) => (
              <>
                <span class="mono">{p().name}</span> <span class="subtle small">v{p().version}</span>
              </>
            )}
          </Show>
        </h2>
        <Show when={p}>{(p) => <p class="mono small subtle">{p().arn}</p>}</Show>
        <Show when={!p}>
          <input
            type="text"
            placeholder="policy-name"
            aria-label="Policy name"
            autocomplete="off"
            required
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
          <input
            type="text"
            placeholder="/path/ (optional)"
            aria-label="Path"
            title="Its ARN has the path before its name (arn:aws:iam::…:policy/team/name), which policies can name"
            autocomplete="off"
            value={path()}
            onInput={(e) => setPath(e.currentTarget.value)}
          />
        </Show>
        <input
          type="text"
          placeholder="What it's for (optional)"
          aria-label="Description"
          readOnly={p?.aws}
          value={description()}
          onInput={(e) => setDescription(e.currentTarget.value)}
        />
        <PolicyEditor document={document()} setDocument={setDocument} buckets={props.buckets} readOnly={p?.aws} />
        <Show when={!p?.aws}>
          <div class="small">Tags</div>
          <TagRows tags={tags()} setTags={setTags} />
          <p class="subtle small">
            Policies see a policy's tags as aws:ResourceTag/… in IAM actions on it (a delegated admin may be let change only
            the policies tagged as theirs, say). Unlike users', a policy's tag keys are case-sensitive, as in IAM.
          </p>
        </Show>
        <Show when={p?.aws}>
          <p class="subtle small">Cairn's policies are AWS's, and can't be changed: make one of your own instead.</p>
        </Show>
        <Show when={versions()?.length}>
          <div class="small">Versions</div>
          <For each={versions()}>
            {(v) => (
              <div class="form-row small">
                <span class="mono">v{v.version}</span>
                <Show when={v.default}>
                  <Badge tone="accent">default</Badge>
                </Show>
                <span class="subtle">{ago(v.created_at)}</span>
                <button type="button" class="small" title="Into the editor: saving makes it a new version" onClick={() => setDocument(pretty(v.document))}>
                  Load
                </button>
                <Show when={!v.default}>
                  <button type="button" class="small" title="It decides, from now on" onClick={() => makeDefault(v.version)}>
                    Make default
                  </button>
                  <button type="button" class="small danger" onClick={() => deleteVersion(v.version)}>
                    Delete
                  </button>
                </Show>
              </div>
            )}
          </For>
          <p class="subtle small">
            A policy keeps up to five versions, as in IAM; the default decides. Saving makes a new default version (and, with
            five already, deletes the oldest that isn't the default, as Terraform does).
          </p>
        </Show>
        <Show when={p && !p.aws && (p.users.length || p.roles.length)}>
          <p class="subtle small">
            Saving makes a new version, which applies to everyone it's attached to at once:{" "}
            {[...p!.users, ...p!.roles.map((r) => `role ${r}`)].join(", ")}.
          </p>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            {p?.aws ? "Close" : "Cancel"}
          </button>
          <Show when={!p?.aws}>
            <button class="primary" type="submit">
              {p ? "Save" : "Create"}
            </button>
          </Show>
        </div>
      </form>
    </dialog>
  );
}

