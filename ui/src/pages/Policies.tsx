// An account's managed policies (see `src/managed.rs`): Cairn's, which have
// AWS's names and say what AWS's do, and the account's own, which are
// attached to users and roles on the Users and Roles pages. Making,
// changing (a new version) and deleting (once nothing has it attached) the
// account's own.

import { For, Show, createResource, createSignal, onMount } from "solid-js";
import { type ManagedPolicy, type Tag, api } from "../api";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { EMPTY, PolicyEditor } from "../components/PolicyEditor";
import { ago, pretty } from "../format";
import { TemplateDialog } from "./Templates";

/** Whether anyone has the policy: attached, or as a boundary. */
const used = (p: ManagedPolicy) => p.users.length + p.bounds.length + p.roles.length + p.role_bounds.length > 0;

export default function Policies() {
  const data = poll(() => Promise.all([api.policies(), api.buckets()]), 10000);
  const [open, setOpen] = createSignal<{ policy?: ManagedPolicy }>();
  const [fromTemplate, setFromTemplate] = createSignal(false);
  const remove = async (p: ManagedPolicy) => {
    if (!confirm(`Delete policy "${p.name}"?`)) return;
    if (await act(() => api.deleteManagedPolicy(p.name), `Deleted ${p.name}`)) data.refresh();
  };
  const buckets = () => (data.data()?.[1] ?? []).map((b) => b.name);
  return (
    <>
      <div class="page-head">
        <h1>Policies</h1>
        <div class="buttons">
          <button onClick={() => setFromTemplate(true)}>From a template</button>
          <button class="primary" onClick={() => setOpen({})}>
            New policy
          </button>
        </div>
      </div>
      <p class="subtle small">
        Managed policies are documents of their own, attached to any number of users and roles (on the Users and Roles
        pages): what a user, or a role's session, may do is what its attached and inline policies allow, and its
        buckets' policies, where they name it; a Deny wins over any Allow. Cairn's own have AWS's names and say what AWS's do, so policies and tools written for AWS
        work as they are. Templates make policies for common setups: above all a team sharing the account, whose admins
        manage its users, roles, policies and buckets and can't get past them.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Panel>
            <Table count={d()[0].length} columns={["Name", "Description", "Attached to", "Version", ""]}>
              <For each={d()[0]}>
                {(p) => (
                  <tr>
                    <td>
                      <span class="mono">{p.name}</span>{" "}
                      <Show when={p.aws}>
                        <Badge>Cairn's (AWS)</Badge>
                      </Show>
                      <Show when={p.path !== "/"}>
                        <div class="subtle small" title={p.arn}>
                          path {p.path}
                        </div>
                      </Show>
                      <Show when={p.tags.length}>
                        <div class="small">
                          <For each={p.tags}>
                            {(t) => (
                              <span class="chip" title="A tag (aws:ResourceTag in IAM actions on the policy)">
                                {t.key}={t.value}
                              </span>
                            )}
                          </For>
                        </div>
                      </Show>
                    </td>
                    <td class="small">{p.description || <span class="subtle">–</span>}</td>
                    <td>
                      <Show when={!used(p)}>
                        <span class="subtle">no one</span>
                      </Show>
                      <For each={p.users}>{(u) => <span class="chip mono">{u}</span>}</For>
                      <For each={p.roles}>
                        {(r) => (
                          <span class="chip mono" title="A role">
                            role {r}
                          </span>
                        )}
                      </For>
                      <Show when={p.bounds.length || p.role_bounds.length}>
                        <div class="small" title="Users and roles whose permissions boundary it is: it caps what their policies allow">
                          boundary of <For each={p.bounds}>{(u) => <span class="chip mono">{u}</span>}</For>
                          <For each={p.role_bounds}>{(r) => <span class="chip mono">role {r}</span>}</For>
                        </div>
                      </Show>
                    </td>
                    <td class="small">
                      v{p.version}
                      <Show when={p.updated_at}>{(t) => <div class="subtle">{ago(t())}</div>}</Show>
                    </td>
                    <td class="actions">
                      <button class="small" onClick={() => setOpen({ policy: p })}>
                        {p.aws ? "View" : "Edit"}
                      </button>
                      <Show when={!p.aws}>
                        <button
                          class="small danger"
                          disabled={used(p)}
                          title={
                            p.users.length || p.roles.length
                              ? "Detach it from its users and roles first"
                              : used(p)
                                ? "It's a permissions boundary: take it off its users and roles first"
                                : ""
                          }
                          onClick={() => remove(p)}
                        >
                          Delete
                        </button>
                      </Show>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={fromTemplate()}>
        <TemplateDialog onClose={() => setFromTemplate(false)} changed={data.refresh} />
      </Show>
      <Show when={open()}>
        {(o) => (
          <ManagedPolicyDialog
            policy={o().policy}
            policies={data.data()?.[0] ?? []}
            buckets={buckets()}
            onClose={() => setOpen(undefined)}
            changed={data.refresh}
          />
        )}
      </Show>
    </>
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
  const setTag = (i: number, change: Partial<Tag>) => setTags(tags().map((t, j) => (j === i ? { ...t, ...change } : t)));
  const wantedTags = () => tags().filter((t) => t.key.trim()).map((t) => ({ key: t.key.trim(), value: t.value }));
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
          <For each={tags()}>
            {(t, i) => (
              <div class="form-row">
                <input type="text" placeholder="key" aria-label="Tag key" value={t.key} onInput={(e) => setTag(i(), { key: e.currentTarget.value })} />
                <input
                  type="text"
                  placeholder="value"
                  aria-label="Tag value"
                  value={t.value}
                  onInput={(e) => setTag(i(), { value: e.currentTarget.value })}
                />
                <button type="button" class="small" onClick={() => setTags(tags().filter((_, j) => j !== i()))}>
                  Remove
                </button>
              </div>
            )}
          </For>
          <button type="button" class="small" disabled={tags().length >= 50} onClick={() => setTags([...tags(), { key: "", value: "" }])}>
            Add tag
          </button>
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

