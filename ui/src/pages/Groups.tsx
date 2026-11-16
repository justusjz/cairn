// An account's IAM groups (see `src/groups.rs`): users whose policies
// include the group's, inline and managed, as if they were their own. So a
// policy is attached once, to the group of those who need it, not to each
// of them.

import { For, Show, createSignal, onMount } from "solid-js";
import { type Group, type ManagedPolicy, api } from "../api";
import { Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { EMPTY, PolicyEditor } from "../components/PolicyEditor";
import { pretty } from "../format";

/** The most groups a user may be in (as in IAM). */
const MAX_GROUPS_PER_USER = 10;

export default function Groups() {
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
  const [creating, setCreating] = createSignal(false);
  const [renaming, setRenaming] = createSignal<Group>();
  const [attaching, setAttaching] = createSignal<Group>();
  const [adding, setAdding] = createSignal<Group>();
  const [editing, setEditing] = createSignal<{ group: string; policy?: string }>();
  const policies = () => data.data()?.[1] ?? [];
  const buckets = () => (data.data()?.[2] ?? []).map((b) => b.name);
  const users = () => data.data()?.[3] ?? [];
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
            <Table count={d()[0].length} empty="No groups yet." columns={["Name", "Members", "Policies", ""]}>
              <For each={d()[0]}>
                {(group) => (
                  <GroupRow
                    group={group}
                    changed={data.refresh}
                    rename={() => setRenaming(group)}
                    attach={() => setAttaching(group)}
                    add={() => setAdding(group)}
                    editPolicy={(policy) => setEditing({ group: group.name, policy })}
                  />
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={creating()}>
        <NewGroupDialog policies={policies()} onClose={() => setCreating(false)} changed={data.refresh} />
      </Show>
      <Show when={renaming()}>
        {(g) => <RenameDialog group={g()} onClose={() => setRenaming(undefined)} changed={data.refresh} />}
      </Show>
      <Show when={attaching()}>
        {(g) => <AttachDialog group={g()} policies={policies()} onClose={() => setAttaching(undefined)} changed={data.refresh} />}
      </Show>
      <Show when={adding()}>
        {(g) => (
          <AddMemberDialog
            group={g()}
            users={users().map((u) => u.name)}
            onClose={() => setAdding(undefined)}
            changed={data.refresh}
          />
        )}
      </Show>
      <Show when={editing()}>
        {(e) => (
          <InlinePolicyDialog
            group={e().group}
            policy={e().policy}
            buckets={buckets()}
            onClose={() => setEditing(undefined)}
            changed={data.refresh}
          />
        )}
      </Show>
    </>
  );
}

function GroupRow(props: {
  group: Group;
  changed: () => void;
  rename: () => void;
  attach: () => void;
  add: () => void;
  editPolicy: (policy?: string) => void;
}) {
  const g = () => props.group;
  const detach = async (name: string, arn: string) => {
    if (!confirm(`Detach ${name} from group "${g().name}"? Its members lose what it allowed them (unless they have it otherwise).`))
      return;
    if (await act(() => api.detachFromGroup(g().name, arn), `Detached ${name}`)) props.changed();
  };
  const remove = async (user: string) => {
    if (!confirm(`Remove ${user} from group "${g().name}"? They lose what its policies allowed them.`)) return;
    if (await act(() => api.removeFromGroup(g().name, user), `Removed ${user} from ${g().name}`)) props.changed();
  };
  const del = async () => {
    if (!confirm(`Delete group "${g().name}"?`)) return;
    if (await act(() => api.deleteGroup(g().name), `Deleted group ${g().name}`)) props.changed();
  };
  const blocker = () =>
    g().members.length
      ? "Remove its members first"
      : g().attached.length + g().policies.length
        ? "Detach its managed policies and delete its inline ones first"
        : "";
  return (
    <tr>
      <td>
        <span class="mono">{g().name}</span>
        <Show when={g().path !== "/"}>
          <div class="subtle small" title={g().arn}>
            path {g().path}
          </div>
        </Show>
        <div class="subtle small mono" title="Its unique ID">
          {g().id}
        </div>
      </td>
      <td>
        <Show when={g().members_shown} fallback={<span class="subtle" title="Its members show to whom may iam:GetGroup it">hidden</span>}>
          <For each={g().members} fallback={<span class="subtle">no one</span>}>
            {(u) => (
              <span class="chip mono">
                {u}
                <button title="Remove from the group" aria-label={`Remove ${u}`} onClick={() => remove(u)}>
                  ×
                </button>
              </span>
            )}
          </For>
        </Show>
        <div class="key-actions">
          <button class="small" onClick={props.add}>
            Add member…
          </button>
        </div>
      </td>
      <td>
        <For each={g().attached}>
          {(a) => (
            <span class="chip" title={a.arn}>
              {a.name}
              <button title="Detach" aria-label={`Detach ${a.name}`} onClick={() => detach(a.name, a.arn)}>
                ×
              </button>
            </span>
          )}
        </For>
        <For each={g().policies}>
          {(p) => (
            <button class="chip policy" title="Its own (inline) policy: view or edit" onClick={() => props.editPolicy(p)}>
              {p}
            </button>
          )}
        </For>
        <Show when={!g().attached.length && !g().policies.length}>
          <div class="subtle">none: it gives its members nothing</div>
        </Show>
        <div class="key-actions">
          <button class="small" onClick={props.attach}>
            Attach…
          </button>
          <button class="small" title="A policy of this group's own" onClick={() => props.editPolicy()}>
            Inline…
          </button>
        </div>
      </td>
      <td class="actions">
        <button class="small" title="Rename or move it" onClick={props.rename}>
          Rename…
        </button>
        <button class="small danger" disabled={!!blocker()} title={blocker()} onClick={del}>
          Delete
        </button>
      </td>
    </tr>
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

/** Managed policies to pick from: the account's, then Cairn's. */
function PolicySelect(props: { policies: ManagedPolicy[]; value: string; setValue: (arn: string) => void; none?: string }) {
  return (
    <select aria-label="Policy" value={props.value} onChange={(e) => props.setValue(e.currentTarget.value)}>
      <Show when={props.none}>
        <option value="">{props.none}</option>
      </Show>
      <optgroup label="The account's">
        <For each={props.policies.filter((p) => !p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
      </optgroup>
      <optgroup label="Cairn's (AWS's)">
        <For each={props.policies.filter((p) => p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
      </optgroup>
    </select>
  );
}

/** A group's new name or path. */
function RenameDialog(props: { group: Group; onClose: () => void; changed: () => void }) {
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
      props.changed();
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

/** Attaching a managed policy to a group: those it doesn't have yet. */
function AttachDialog(props: { group: Group; policies: ManagedPolicy[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const open = () => props.policies.filter((p) => !props.group.attached.some((a) => a.arn === p.arn));
  const [arn, setArn] = createSignal(open().find((p) => !p.aws)?.arn ?? open()[0]?.arn ?? "");
  const chosen = () => props.policies.find((p) => p.arn === arn());
  const attach = async (e: SubmitEvent) => {
    e.preventDefault();
    const p = chosen();
    if (!p) return;
    if (await act(() => api.attachToGroup(props.group.name, p.arn), `Attached ${p.name} to ${props.group.name}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={attach}>
        <h2>
          Attach a policy to <span class="mono">{props.group.name}</span>
        </h2>
        <Show when={open().length} fallback={<p class="subtle">Every policy is attached already.</p>}>
          <PolicySelect policies={open()} value={arn()} setValue={setArn} />
          <Show when={chosen()}>
            {(p) => (
              <>
                <p class="subtle small">{p().description}</p>
                <div class="pem">{pretty(p().document)}</div>
              </>
            )}
          </Show>
        </Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={!chosen()}>
            Attach
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** A group's inline policy, to view, edit or delete (`policy`), or a new one. */
function InlinePolicyDialog(props: { group: string; policy?: string; buckets: string[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  const [name, setName] = createSignal(props.policy ?? "");
  const [document, setDocument] = createSignal(props.policy ? "" : EMPTY);
  const [loading, setLoading] = createSignal(!!props.policy);
  const [error, setError] = createSignal<string>();
  onMount(async () => {
    dialog.showModal();
    if (!props.policy) return;
    try {
      setDocument(pretty((await api.groupPolicy(props.group, props.policy)).document));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setLoading(false);
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.putGroupPolicy(props.group, n, document());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved policy ${n} of ${props.group}`);
    props.changed();
    dialog.close();
  };
  const remove = async () => {
    if (!confirm(`Delete policy "${props.policy}" of group "${props.group}"?`)) return;
    if (await act(() => api.deleteGroupPolicy(props.group, props.policy!), `Deleted policy ${props.policy}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          {props.policy ? "Inline policy" : "New inline policy"} of <span class="mono">{props.group}</span>
        </h2>
        <Show when={!props.policy} fallback={<p class="mono">{props.policy}</p>}>
          <input
            type="text"
            placeholder="policy-name"
            aria-label="Policy name"
            autocomplete="off"
            required
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </Show>
        <PolicyEditor document={document()} setDocument={setDocument} buckets={props.buckets} disabled={loading()} />
        <p class="subtle small">A group's inline policies hold at most 5,120 characters together (but whitespace).</p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <Show when={props.policy}>
            <button type="button" class="danger" onClick={remove}>
              Delete
            </button>
          </Show>
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={loading()}>
            Save
          </button>
        </div>
      </form>
    </dialog>
  );
}
