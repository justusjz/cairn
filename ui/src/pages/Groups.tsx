// An account's IAM groups (see `src/groups.rs`): users whose policies
// include the group's, inline and managed, as if they were their own. So a
// policy is attached once, to the group of those who need it, not to each
// of them. The list, a new group, and a group's own page.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type Group, type ManagedPolicy, api } from "../api";
import {
  AttachDialog,
  Chip,
  DetailHead,
  Gone,
  InlinePolicyDialog,
  PermissionsPanel,
  PolicyChips,
  PolicySelect,
  groupHref,
  userHref,
} from "../components/Iam";
import { Loading, Panel, Table, act, poll, toast } from "../components/ui";

/** The most groups a user may be in (as in IAM). */
const MAX_GROUPS_PER_USER = 10;

export default function Groups() {
  const data = poll(() => Promise.all([api.groups(), api.policies()]), 10000);
  const [creating, setCreating] = createSignal(false);
  return (
    <>
      <div class="page-head">
        <h1>Groups</h1>
        <button class="primary" onClick={() => setCreating(true)}>
          New group
        </button>
      </div>
      <p class="subtle small">
        A group's policies, attached and inline, are each of its members' as if they were their own: attach{" "}
        <span class="mono">invoices-read</span> to the group of those who read invoices, not to each of them. A user may be
        in up to {MAX_GROUPS_PER_USER} groups, and its permissions boundary caps what they allow it too. Groups aren't
        principals: a bucket's or role's trust policy can't name one.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Panel>
            <Table count={d()[0].length} empty="No groups yet." columns={["Name", "Members", "Permissions"]}>
              <For each={d()[0]}>
                {(g) => (
                  <tr>
                    <td>
                      <A class="mono" href={groupHref(g.name)}>
                        {g.name}
                      </A>
                      <Show when={g.path !== "/"}>
                        <div class="subtle small" title={g.arn}>
                          path {g.path}
                        </div>
                      </Show>
                    </td>
                    <td>
                      <Members group={g} />
                    </td>
                    <td>
                      <PolicyChips attached={g.attached} inline={g.policies} none="none: it gives its members nothing" />
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={creating()}>
        <NewGroupDialog policies={data.data()?.[1] ?? []} onClose={() => setCreating(false)} changed={data.refresh} />
      </Show>
    </>
  );
}

/** A group's members, as links (if the session may see them). */
function Members(props: { group: Group }) {
  return (
    <Show when={props.group.members_shown} fallback={<span class="subtle" title="Its members show to whom may iam:GetGroup it">hidden</span>}>
      <For each={props.group.members} fallback={<span class="subtle">no one</span>}>
        {(u) => <Chip href={userHref(u)}>{u}</Chip>}
      </For>
    </Show>
  );
}

/** A new group: its name and path, and a policy to attach. */
function NewGroupDialog(props: { policies: ManagedPolicy[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal("");
  const [path, setPath] = createSignal("");
  const [attach, setAttach] = createSignal("");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.createGroup(n, path().trim());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Created group ${n}`);
    if (attach()) await act(() => api.attachToGroup(n, attach()), `Attached ${attach().split("/").pop()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>New group</h2>
        <div class="form-row">
          <input
            type="text"
            placeholder="group-name"
            aria-label="Group name"
            autocomplete="off"
            required
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
          <input
            type="text"
            placeholder="/path/ (optional)"
            aria-label="Path"
            title="Where the group is: its ARN has the path before its name (arn:aws:iam::…:group/team/name), which policies can name"
            autocomplete="off"
            value={path()}
            onInput={(e) => setPath(e.currentTarget.value)}
          />
        </div>
        <PolicySelect policies={props.policies} value={attach()} setValue={setAttach} none="No policy yet (attach or write one later)" />
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Create
          </button>
        </div>
      </form>
    </dialog>
  );
}

// ─── A group's page ──────────────────────────────────────────────────────────

export function GroupPage() {
  const params = useParams();
  const navigate = useNavigate();
  const name = () => params.name!;
  const data = poll(
    () =>
      Promise.all([
        api.groups(),
        api.policies(),
        api.buckets(),
        // Whom to add: the users the session may list (none, if it may list none).
        api.users().catch(() => []),
      ]),
    10000,
  );
  const group = () => data.data()?.[0].find((g) => g.name === name());
  const [renaming, setRenaming] = createSignal(false);
  const [attaching, setAttaching] = createSignal(false);
  const [adding, setAdding] = createSignal(false);
  const [inline, setInline] = createSignal<{ policy?: string }>();

  const detach = async (policy: string, arn: string) => {
    if (!confirm(`Detach ${policy} from group "${name()}"? Its members lose what it allowed them (unless they have it otherwise).`))
      return;
    if (await act(() => api.detachFromGroup(name(), arn), `Detached ${policy}`)) data.refresh();
  };
  const removeMember = async (user: string) => {
    if (!confirm(`Remove ${user} from group "${name()}"? They lose what its policies allowed them.`)) return;
    if (await act(() => api.removeFromGroup(name(), user), `Removed ${user} from ${name()}`)) data.refresh();
  };
  const blocker = () => {
    const g = group();
    if (!g) return "";
    return g.members.length
      ? "Remove its members first"
      : g.attached.length + g.policies.length
        ? "Detach its managed policies and delete its inline ones first"
        : "";
  };
  const remove = async () => {
    if (!confirm(`Delete group "${name()}"?`)) return;
    if (await act(() => api.deleteGroup(name()), `Deleted group ${name()}`)) navigate("/groups");
  };

  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      <Show when={group()} fallback={<Gone kind="Groups" href="/groups" name={name()} />}>
        {(g) => (
          <>
            <DetailHead kind="Groups" href="/groups" name={g().name}>
              <button title="Rename or move it" onClick={() => setRenaming(true)}>
                Rename…
              </button>
              <button class="danger" disabled={!!blocker()} title={blocker()} onClick={remove}>
                Delete
              </button>
            </DetailHead>
            <Panel title="Summary">
              <dl class="kv">
                <dt>ARN</dt>
                <dd class="mono">{g().arn}</dd>
                <dt>Path</dt>
                <dd class="mono">{g().path}</dd>
                <dt>ID</dt>
                <dd class="mono">{g().id}</dd>
              </dl>
            </Panel>
            <Panel title="Members" note={g().members_shown ? `${g().members.length}` : undefined}>
              <Show
                when={g().members_shown}
                fallback={<p class="subtle">Its members show to whom may iam:GetGroup it.</p>}
              >
                <Table count={g().members.length} empty="No one." columns={["User", ""]}>
                  <For each={g().members}>
                    {(u) => (
                      <tr>
                        <td>
                          <A class="mono" href={userHref(u)}>
                            {u}
                          </A>
                        </td>
                        <td class="actions">
                          <button class="small" onClick={() => removeMember(u)}>
                            Remove
                          </button>
                        </td>
                      </tr>
                    )}
                  </For>
                </Table>
              </Show>
              <div class="key-actions">
                <button class="small" onClick={() => setAdding(true)}>
                  Add a member…
                </button>
              </div>
            </Panel>
            <PermissionsPanel
              attached={g().attached}
              inline={g().policies}
              none="None: it gives its members nothing."
              detach={detach}
              editInline={(policy) => setInline({ policy })}
              attach={() => setAttaching(true)}
              note={<p class="subtle small">A group's inline policies hold at most 5,120 characters together (but whitespace).</p>}
            />

            <Show when={renaming()}>
              <RenameDialog
                group={g()}
                onClose={() => setRenaming(false)}
                changed={(renamed) => {
                  if (renamed) navigate(groupHref(renamed), { replace: true });
                  data.refresh();
                }}
              />
            </Show>
            <Show when={attaching()}>
              <AttachDialog
                target={g().name}
                attached={g().attached.map((a) => a.arn)}
                policies={data.data()?.[1] ?? []}
                attach={(arn) => api.attachToGroup(g().name, arn)}
                onClose={() => setAttaching(false)}
                changed={data.refresh}
              />
            </Show>
            <Show when={adding()}>
              <AddMemberDialog
                group={g()}
                users={(data.data()?.[3] ?? []).map((u) => u.name)}
                onClose={() => setAdding(false)}
                changed={data.refresh}
              />
            </Show>
            <Show when={inline()}>
              {(i) => (
                <InlinePolicyDialog
                  owner={`group ${g().name}`}
                  policy={i().policy}
                  buckets={(data.data()?.[2] ?? []).map((b) => b.name)}
                  load={(p) => api.groupPolicy(g().name, p)}
                  save={(p, doc) => api.putGroupPolicy(g().name, p, doc)}
                  remove={(p) => api.deleteGroupPolicy(g().name, p)}
                  onClose={() => setInline(undefined)}
                  changed={data.refresh}
                />
              )}
            </Show>
          </>
        )}
      </Show>
    </Show>
  );
}

/** A group's new name or path. `changed` gets its new name if renamed. */
function RenameDialog(props: { group: Group; onClose: () => void; changed: (renamed?: string) => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal(props.group.name);
  const [path, setPath] = createSignal(props.group.path);
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const change = {
      name: name().trim() !== props.group.name ? name().trim() : undefined,
      path: path().trim() !== props.group.path ? path().trim() : undefined,
    };
    if (!change.name && !change.path) return dialog.close();
    if (await act(() => api.updateGroup(props.group.name, change), `Changed group ${props.group.name}`)) {
      props.changed(change.name);
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          <span class="mono">{props.group.name}</span>
        </h2>
        <p class="subtle small mono">{props.group.arn}</p>
        <label class="field">
          Name
          <input type="text" required value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Path
          <input type="text" required value={path()} onInput={(e) => setPath(e.currentTarget.value)} />
        </label>
        <p class="subtle small">
          Renaming or moving a group changes its ARN: policies that name it there (who may manage it) see it at the new
          one. Its members and policies stay.
        </p>
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

/** Adding a user to a group: those not in it yet, or one by name. */
function AddMemberDialog(props: { group: Group; users: string[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const open = () => props.users.filter((u) => !props.group.members.includes(u));
  const [user, setUser] = createSignal(open()[0] ?? "");
  const add = async (e: SubmitEvent) => {
    e.preventDefault();
    const u = user().trim();
    if (!u) return;
    if (await act(() => api.addToGroup(props.group.name, u), `Added ${u} to ${props.group.name}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={add}>
        <h2>
          Add a member to <span class="mono">{props.group.name}</span>
        </h2>
        <Show
          when={open().length}
          fallback={
            <input
              type="text"
              placeholder="user-name"
              aria-label="User name"
              required
              value={user()}
              onInput={(e) => setUser(e.currentTarget.value)}
            />
          }
        >
          <select aria-label="User" value={user()} onChange={(e) => setUser(e.currentTarget.value)}>
            <For each={open()}>{(u) => <option value={u}>{u}</option>}</For>
          </select>
        </Show>
        <p class="subtle small">They get what the group's policies allow, as long as they're in it.</p>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={!user().trim()}>
            Add
          </button>
        </div>
      </form>
    </dialog>
  );
}
