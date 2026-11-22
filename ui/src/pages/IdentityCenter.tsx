// Identity Center (see `src/identity_center.rs`), the management account's:
// the permission sets directory users act with, provisioned as roles to the
// accounts they're assigned in, the assignments that give them to users and
// groups in an account, and the directory: Cairn's own users and groups, and
// those of the identity sources (set up on the Sign-in page) that have signed
// in. The page, and a permission set's own page.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type Assignment, type DirectoryGroup, type DirectoryUser, type OrgAccount, type ManagedPolicy, type PermissionSet, api } from "../api";
import { AccountName } from "../components/AccountName";
import { AttachDialog, DetailHead, Gone, InlinePolicyDialog, PermissionsPanel, PolicyChips, PolicySelect, roleHref } from "../components/Iam";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { ago, date } from "../format";

/** The name of a permission set's inline policy, as Identity Center names it. */
const INLINE = "AwsSSOInlinePolicy";

const setHref = (name: string) => `/identity-center/${encodeURIComponent(name)}`;
const hours = (seconds: number) => `${Math.round(seconds / 360) / 10} h`;

export default function IdentityCenter() {
  const data = poll(
    () => Promise.all([api.permissionSets(), api.assignments(), api.directoryUsers().catch(() => []), api.directoryGroups().catch(() => [])]),
    10000,
  );
  const [creating, setCreating] = createSignal(false);
  const [assigning, setAssigning] = createSignal(false);
  const [newUser, setNewUser] = createSignal(false);
  const [link, setLink] = createSignal<{ user: string; url?: string | null; path: string }>();
  const setupLink = async (u: DirectoryUser) => {
    const made = await act(() => api.directorySetupLink(u.id));
    if (made) {
      setLink({ user: u.user_name, ...made.value });
      data.refresh();
    }
  };
  const removePasskeys = async (u: DirectoryUser) => {
    if (!confirm(`Remove all of ${u.user_name}'s passkeys? Their sessions end, and they need a setup link to sign in again.`)) return;
    if (await act(() => api.deleteDirectoryPasskeys(u.id), `Removed ${u.user_name}'s passkeys`)) data.refresh();
  };
  const deleteUser = async (u: DirectoryUser) => {
    if (!confirm(`Delete ${u.user_name}? Their assignments, group memberships and passkeys go too.`)) return;
    if (await act(() => api.deleteDirectoryUser(u.id), `Deleted ${u.user_name}`)) data.refresh();
  };
  const deleteGroup = async (g: DirectoryGroup) => {
    if (!confirm(`Delete group ${g.name}? Its assignments go too, and with them its members' access through it.`)) return;
    if (await act(() => api.deleteDirectoryGroup(g.id), `Deleted ${g.name}`)) data.refresh();
  };
  const removeMember = async (g: DirectoryGroup, m: DirectoryGroup["memberships"][number]) => {
    if (!confirm(`Take ${m.user_name} out of ${g.name}? They lose what its assignments gave them at once.`)) return;
    if (await act(() => api.removeGroupMember(g.id, m.id), `Took ${m.user_name} out of ${g.name}`)) data.refresh();
  };
  const [editingUser, setEditingUser] = createSignal<DirectoryUser>();
  const [editingGroup, setEditingGroup] = createSignal<DirectoryGroup | "new">();
  const [addingTo, setAddingTo] = createSignal<DirectoryGroup>();
  const unassign = async (a: Assignment) => {
    const who = a.principal_type === "GROUP" ? `group ${a.principal_name}` : a.principal_name;
    if (!confirm(`Take ${a.permission_set} from ${who}? Their sessions lose it at once.`)) return;
    if (await act(() => api.unassign(a.id), `Took ${a.permission_set} from ${who}`)) data.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Identity Center</h1>
        <div class="buttons">
          <button onClick={() => setAssigning(true)}>Assign…</button>
          <button class="primary" onClick={() => setCreating(true)}>
            New permission set
          </button>
        </div>
      </div>
      <p class="subtle small">
        As in IAM Identity Center, directory users have no IAM user: users of Cairn's own directory, made here, who
        sign in with passkeys, and people who sign in at an identity source (set up on the{" "}
        <A href="/sign-in">Sign-in</A> page). They use the permission sets assigned to them, or to their groups, in an
        account of the organization. A permission set is provisioned to each account it's assigned in, as a role at{" "}
        <span class="mono">/aws-reserved/sso.amazonaws.com/</span> there, which only Identity Center changes; signed in,
        a directory user acts as a session of that role.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <>
            <Panel title="Permission sets">
              <Table count={d()[0].length} empty="None yet." columns={["Name", "Policies", "Sessions", { label: "Assignments", num: true }]}>
                <For each={d()[0]}>
                  {(s) => (
                    <tr>
                      <td>
                        <A class="mono" href={setHref(s.name)}>
                          {s.name}
                        </A>
                        <Show when={s.description}>
                          <div class="subtle small">{s.description}</div>
                        </Show>
                      </td>
                      <td>
                        <PolicyChips attached={s.attached} inline={s.inline_policy ? [INLINE] : []} none="none" />
                      </td>
                      <td>{hours(s.session_duration)}</td>
                      <td class="num">{s.assignments}</td>
                    </tr>
                  )}
                </For>
              </Table>
            </Panel>
            <Panel title="Assignments">
              <Table count={d()[1].length} empty="None: no directory user can sign in yet." columns={["Permission set", "Account", "To", "Source", "Since", ""]}>
                <For each={d()[1]}>
                  {(a) => (
                    <tr>
                      <td>
                        <A class="mono" href={setHref(a.permission_set)}>
                          {a.permission_set}
                        </A>
                      </td>
                      <td>
                        <AccountName id={a.account_id} />
                      </td>
                      <td>
                        <Show
                          when={a.principal_type === "USER"}
                          fallback={
                            <>
                              <Badge>group</Badge> <span class="mono">{a.principal_name}</span>
                            </>
                          }
                        >
                          {a.principal_name}
                          <Show when={a.email}>{(e) => <div class="subtle small mono">{e()}</div>}</Show>
                        </Show>
                      </td>
                      <td class="mono small">{a.provider ?? "Cairn"}</td>
                      <td>{date(a.created_at)}</td>
                      <td class="actions">
                        <button class="small danger" onClick={() => unassign(a)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </Table>
            </Panel>
            <Panel title="Directory users" note={`${d()[2].length}`}>
              <div class="buttons">
                <button onClick={() => setNewUser(true)}>New user…</button>
              </div>
              <Table count={d()[2].length} empty="No directory user yet." columns={["Name", "Source", "Groups", "Last signed in", ""]}>
                <For each={d()[2]}>
                  {(u) => (
                    <tr>
                      <td>
                        {u.display_name}
                        <div class="subtle small mono">{u.user_name}</div>
                      </td>
                      <td class="small">
                        <Show when={u.provider} fallback={
                          <>
                            Cairn{" "}
                            <span class="subtle">
                              · {u.passkeys} passkey{u.passkeys === 1 ? "" : "s"}
                              {u.setup_link_pending ? " · link out" : ""}
                            </span>
                          </>
                        }>
                          {(p) => <span class="mono">{p()}</span>}
                        </Show>
                      </td>
                      <td>
                        <For each={u.groups} fallback={<span class="subtle">none</span>}>
                          {(g) => <span class="chip mono">{g}</span>}
                        </For>
                      </td>
                      <td>
                        {u.provider ? ago(u.last_signed_in) : u.last_passkey_use ? ago(u.last_passkey_use) : <span class="subtle">never</span>}
                      </td>
                      <td class="actions">
                        <Show when={!u.provider}>
                          <button class="small" onClick={() => setEditingUser(u)}>
                            Edit…
                          </button>
                          <button class="small" onClick={() => setupLink(u)}>
                            Setup link
                          </button>
                          <Show when={u.passkeys > 0}>
                            <button class="small" onClick={() => removePasskeys(u)}>
                              Remove passkeys
                            </button>
                          </Show>
                          <button class="small danger" onClick={() => deleteUser(u)}>
                            Delete
                          </button>
                        </Show>
                      </td>
                    </tr>
                  )}
                </For>
              </Table>
              <p class="subtle small">
                Users of Cairn's own directory sign in with passkeys, which they make with a setup link (valid 7 days).
                Those of an identity source are here once they've signed in there, with their groups as it last said:
                there's no directory sync.
              </p>
            </Panel>
            <Show when={newUser()}>
              <NewDirectoryUserDialog
                onClose={() => setNewUser(false)}
                created={(user, made) => {
                  setLink({ user, ...made });
                  data.refresh();
                }}
              />
            </Show>
            <Show when={link()}>{(l) => <SetupLinkDialog {...l()} onClose={() => setLink(undefined)} />}</Show>
            <Show when={editingUser()} keyed>
              {(u) => <EditDirectoryUserDialog user={u} onClose={() => setEditingUser(undefined)} changed={data.refresh} />}
            </Show>
            <Panel title="Groups" note={`${d()[3].length}`}>
              <div class="buttons">
                <button onClick={() => setEditingGroup("new")}>New group…</button>
              </div>
              <Table count={d()[3].length} empty="No group yet." columns={["Name", "Source", "Members", ""]}>
                <For each={d()[3]}>
                  {(g) => (
                    <tr>
                      <td>
                        <span class="mono">{g.name}</span>
                        <Show when={g.description}>{(text) => <div class="subtle small">{text()}</div>}</Show>
                      </td>
                      <td class="small">
                        <Show when={g.provider} fallback="Cairn">
                          {(p) => <span class="mono">{p()}</span>}
                        </Show>
                      </td>
                      <td>
                        <For each={g.memberships} fallback={<span class="subtle">none</span>}>
                          {(m) => (
                            <span class="chip mono">
                              {m.user_name}
                              <Show when={!g.provider}>
                                {" "}
                                <button class="link small" title={`Take ${m.user_name} out`} onClick={() => removeMember(g, m)}>
                                  ×
                                </button>
                              </Show>
                            </span>
                          )}
                        </For>
                      </td>
                      <td class="actions">
                        <Show when={!g.provider}>
                          <button class="small" onClick={() => setAddingTo(g)}>
                            Add member…
                          </button>
                          <button class="small" onClick={() => setEditingGroup(g)}>
                            Edit…
                          </button>
                          <button class="small danger" onClick={() => deleteGroup(g)}>
                            Delete
                          </button>
                        </Show>
                      </td>
                    </tr>
                  )}
                </For>
              </Table>
              <p class="subtle small">
                Groups of Cairn's own directory may have any directory user as a member, an identity source's too, whose
                sign-ins leave those memberships alone. An identity source's groups are what its group claim last said.
              </p>
            </Panel>
            <Show when={editingGroup()} keyed>
              {(g) => (
                <GroupDialog group={g === "new" ? undefined : g} onClose={() => setEditingGroup(undefined)} changed={data.refresh} />
              )}
            </Show>
            <Show when={addingTo()} keyed>
              {(g) => <AddMemberDialog group={g} users={d()[2]} onClose={() => setAddingTo(undefined)} changed={data.refresh} />}
            </Show>
            <Show when={creating()}>
              <NewPermissionSetDialog onClose={() => setCreating(false)} changed={data.refresh} />
            </Show>
            <Show when={assigning()}>
              <AssignDialog sets={d()[0]} users={d()[2]} groups={d()[3]} onClose={() => setAssigning(false)} changed={data.refresh} />
            </Show>
          </>
        )}
      </Show>
    </>
  );
}

function NewPermissionSetDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const navigate = useNavigate();
  const [name, setName] = createSignal("");
  const [description, setDescription] = createSignal("");
  const [duration, setDuration] = createSignal(1);
  const [error, setError] = createSignal<string>();
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      await api.createPermissionSet(name().trim(), description(), duration() * 3600);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Made permission set ${name()}`);
    props.changed();
    dialog.close();
    navigate(setHref(name().trim()));
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={create}>
        <h2>New permission set</h2>
        <label class="field">
          Name
          <input type="text" required maxLength={32} value={name()} onInput={(e) => setName(e.currentTarget.value)} placeholder="DataScience" />
        </label>
        <label class="field">
          Description
          <input type="text" maxLength={700} value={description()} onInput={(e) => setDescription(e.currentTarget.value)} />
        </label>
        <label class="field">
          Sessions last (hours)
          <input type="number" min={1} max={12} required value={duration()} onInput={(e) => setDuration(Number(e.currentTarget.value))} />
        </label>
        <p class="subtle small">Then give it policies, on its page, and assign it to people or groups.</p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Make it
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** Assigns a permission set to a directory user or group of the identity
 * store (one someone has signed in with). */
function AssignDialog(props: {
  sets: PermissionSet[];
  users: DirectoryUser[];
  groups: DirectoryGroup[];
  set?: string;
  onClose: () => void;
  changed: () => void;
}) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [set, setSet] = createSignal(props.set ?? props.sets[0]?.name ?? "");
  const [kind, setKind] = createSignal<"GROUP" | "USER">(props.groups.length ? "GROUP" : "USER");
  const options = () =>
    kind() === "GROUP"
      ? props.groups.map((g) => ({ id: g.id, label: `${g.name} (${g.provider ?? "Cairn"})` }))
      : props.users.map((u) => ({ id: u.id, label: `${u.display_name} (${u.user_name})` }));
  const [chosen, setChosen] = createSignal("");
  const principal = () => (options().some((o) => o.id === chosen()) ? chosen() : (options()[0]?.id ?? ""));
  // The organization's open accounts, to assign in (this one's only, if
  // the session can't list them).
  const [accounts, setAccounts] = createSignal<OrgAccount[]>([]);
  const [account, setAccount] = createSignal("");
  onMount(async () => {
    try {
      const all = (await api.accounts()).filter((a) => a.status === "ACTIVE");
      setAccounts(all);
      setAccount(all.find((a) => a.management)?.id ?? all[0]?.id ?? "");
    } catch {
      setAccounts([]);
    }
  });
  const [error, setError] = createSignal<string>();
  const assign = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      await api.assign(set(), kind(), principal(), account() || undefined);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Assigned ${set()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={assign}>
        <h2>Assign a permission set</h2>
        <Show when={props.sets.length} fallback={<p class="subtle">Make a permission set first.</p>}>
          <label class="field">
            Permission set
            <select value={set()} onChange={(e) => setSet(e.currentTarget.value)}>
              <For each={props.sets}>{(s) => <option value={s.name}>{s.name}</option>}</For>
            </select>
          </label>
          <Show when={accounts().length > 1}>
            <label class="field">
              In account
              <select value={account()} onChange={(e) => setAccount(e.currentTarget.value)}>
                <For each={accounts()}>{(a) => <option value={a.id}>{`${a.name} (${a.id})`}</option>}</For>
              </select>
            </label>
          </Show>
          <label class="field">
            To
            <select value={kind()} onChange={(e) => setKind(e.currentTarget.value as "GROUP" | "USER")}>
              <option value="GROUP">a group</option>
              <option value="USER">a user</option>
            </select>
          </label>
          <Show
            when={options().length}
            fallback={
              <p class="subtle small">
                No {kind() === "GROUP" ? "group" : "user"} yet: make one on the Identity Center page, or have someone
                sign in at an identity source.
              </p>
            }
          >
            <label class="field">
              {kind() === "GROUP" ? "Group" : "User"}
              <select value={principal()} onChange={(e) => setChosen(e.currentTarget.value)}>
                <For each={options()}>{(o) => <option value={o.id}>{o.label}</option>}</For>
              </select>
            </label>
          </Show>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={!props.sets.length || !principal()}>
            Assign
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** A permission set's own page: its policies, sessions, and assignments. */
export function PermissionSetPage() {
  const params = useParams();
  const navigate = useNavigate();
  const name = () => params.name!;
  const data = poll(
    () =>
      Promise.all([
        api.permissionSets(),
        api.assignments(),
        api.policies(),
        api.buckets(),
        api.directoryUsers().catch(() => []),
        api.directoryGroups().catch(() => []),
      ]),
    10000,
  );
  const set = () => data.data()?.[0].find((s) => s.name === name());
  const assignments = () => (data.data()?.[1] ?? []).filter((a) => a.permission_set === name());
  const [attaching, setAttaching] = createSignal(false);
  const [editingInline, setEditingInline] = createSignal(false);
  const [editing, setEditing] = createSignal(false);
  const [assigning, setAssigning] = createSignal(false);
  const [bounding, setBounding] = createSignal(false);
  const unbound = async () => {
    if (!confirm(`Take ${name()}'s permissions boundary off? Its users may then do all its policies allow.`)) return;
    if (await act(() => api.deletePermissionSetBoundary(name()), "Boundary removed")) data.refresh();
  };
  const detach = async (policy: string, arn: string) => {
    if (!confirm(`Detach ${policy} from ${name()}? Its users lose what it allowed them at once.`)) return;
    if (await act(() => api.detachFromPermissionSet(name(), arn), `Detached ${policy}`)) data.refresh();
  };
  const provision = async () => {
    if (await act(() => api.provisionPermissionSet(name()), `Provisioned ${name()}`)) data.refresh();
  };
  const remove = async () => {
    if (!confirm(`Delete permission set ${name()}? Its assignments and its roles in every account go too, and with them its users' access.`)) return;
    if (await act(() => api.deletePermissionSet(name()), `Deleted ${name()}`)) navigate("/identity-center");
  };
  const empty = '{\n  "Version": "2012-10-17",\n  "Statement": []\n}';
  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      <Show when={set()} fallback={<Gone kind="Identity Center" href="/identity-center" name={name()} />}>
        {(s) => (
          <>
            <DetailHead kind="Identity Center" href="/identity-center" name={s().name}>
              <button onClick={() => setEditing(true)}>Edit…</button>
              <button class="danger" onClick={remove}>
                Delete
              </button>
            </DetailHead>
            <Panel title="Summary">
              <dl class="kv">
                <dt>ARN</dt>
                <dd class="mono">{s().arn}</dd>
                <dt>Description</dt>
                <dd>{s().description || <span class="subtle">none</span>}</dd>
                <dt>Sessions</dt>
                <dd>{hours(s().session_duration)}</dd>
                <dt>Boundary</dt>
                <dd>
                  <Show when={s().boundary} fallback={<span class="subtle">none </span>}>
                    {(b) => <span class="mono small">{b()} </span>}
                  </Show>
                  <button class="small" onClick={() => setBounding(true)}>
                    {s().boundary ? "Change…" : "Set…"}
                  </button>
                  <Show when={s().boundary}>
                    <button class="small" onClick={unbound}>
                      Remove
                    </button>
                  </Show>
                </dd>
                <dt>Provisioned to</dt>
                <dd>
                  <For
                    each={s().provisioned}
                    fallback={<span class="subtle">no account yet: it's provisioned when it's first assigned</span>}
                  >
                    {(p) => (
                      <div>
                        <AccountName id={p.account_id} compact />{" "}
                        <Show when={p.account_id === s().account_id} fallback={<span class="mono" title={p.role_arn}>{s().role_name}</span>}>
                          <A class="mono" href={roleHref(s().role_name)} title={p.role_arn}>
                            {s().role_name}
                          </A>
                        </Show>{" "}
                        <Show when={!p.latest}>
                          <Badge tone="warn">not the latest</Badge>
                        </Show>
                      </div>
                    )}
                  </For>
                  <Show when={s().provisioned.some((p) => !p.latest)}>
                    <button class="small" onClick={provision}>
                      Provision again
                    </button>
                    <div class="subtle small">
                      Some roles don't hold the set as it is now: it was changed by a session that may not provision it,
                      or through sso-admin, or provisioning failed.
                    </div>
                  </Show>
                </dd>
              </dl>
            </Panel>
            <PermissionsPanel
              attached={s().attached}
              inline={s().inline_policy ? [INLINE] : []}
              none="None: it allows nothing."
              detach={detach}
              editInline={() => setEditingInline(true)}
              attach={() => setAttaching(true)}
              note={<p class="subtle small">A permission set has one inline policy, {INLINE}, as in Identity Center.</p>}
            />
            <Panel title="Assignments" note={`${assignments().length}`}>
              <Table count={assignments().length} empty="None: no one uses it." columns={["Account", "To", "Source"]}>
                <For each={assignments()}>
                  {(a) => (
                    <tr>
                      <td>
                        <AccountName id={a.account_id} />
                      </td>
                      <td>
                        <Show when={a.principal_type === "USER"} fallback={<><Badge>group</Badge> <span class="mono">{a.principal_name}</span></>}>
                          {a.principal_name}
                        </Show>
                      </td>
                      <td class="mono small">{a.provider ?? "Cairn"}</td>
                    </tr>
                  )}
                </For>
              </Table>
              <div class="key-actions">
                <button class="small" onClick={() => setAssigning(true)}>
                  Assign…
                </button>
              </div>
            </Panel>

            <Show when={attaching()}>
              <AttachDialog
                target={s().name}
                attached={s().attached.map((a) => a.arn)}
                policies={data.data()?.[2] ?? []}
                attach={(arn) => api.attachToPermissionSet(s().name, arn)}
                onClose={() => setAttaching(false)}
                changed={data.refresh}
              />
            </Show>
            <Show when={editingInline()}>
              <InlinePolicyDialog
                owner={`permission set ${s().name}`}
                policy={INLINE}
                buckets={(data.data()?.[3] ?? []).map((b) => b.name)}
                load={() => (s().inline_policy ? api.permissionSetPolicy(s().name) : Promise.resolve({ document: empty }))}
                save={(_, doc) => api.putPermissionSetPolicy(s().name, doc)}
                remove={() => api.deletePermissionSetPolicy(s().name)}
                onClose={() => setEditingInline(false)}
                changed={data.refresh}
              />
            </Show>
            <Show when={bounding()}>
              <BoundaryDialog set={s()} policies={data.data()?.[2] ?? []} onClose={() => setBounding(false)} changed={data.refresh} />
            </Show>
            <Show when={editing()}>
              <EditDialog set={s()} onClose={() => setEditing(false)} changed={data.refresh} />
            </Show>
            <Show when={assigning()}>
              <AssignDialog
                sets={data.data()?.[0] ?? []}
                users={data.data()?.[4] ?? []}
                groups={data.data()?.[5] ?? []}
                set={s().name}
                onClose={() => setAssigning(false)}
                changed={data.refresh}
              />
            </Show>
          </>
        )}
      </Show>
    </Show>
  );
}

function EditDialog(props: { set: PermissionSet; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [description, setDescription] = createSignal(props.set.description);
  const [duration, setDuration] = createSignal(props.set.session_duration / 3600);
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      await api.updatePermissionSet(props.set.name, description(), Math.round(duration() * 3600));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved ${props.set.name}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          Edit <span class="mono">{props.set.name}</span>
        </h2>
        <label class="field">
          Description
          <input type="text" maxLength={700} value={description()} onInput={(e) => setDescription(e.currentTarget.value)} />
        </label>
        <label class="field">
          Sessions last (hours)
          <input type="number" min={1} max={12} step="any" required value={duration()} onInput={(e) => setDuration(Number(e.currentTarget.value))} />
        </label>
        <p class="subtle small">Sessions and credentials already handed out keep their duration.</p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
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

/** Sets a permission set's permissions boundary: a managed policy, AWS's or
 * the account's, which caps what its policies allow. */
function BoundaryDialog(props: { set: PermissionSet; policies: ManagedPolicy[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [arn, setArn] = createSignal(props.set.boundary ?? props.policies[0]?.arn ?? "");
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.setPermissionSetBoundary(props.set.name, arn()), "Boundary set")) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          Permissions boundary of <span class="mono">{props.set.name}</span>
        </h2>
        <PolicySelect policies={props.policies} value={arn()} setValue={setArn} label="Boundary" />
        <p class="subtle small">Its users may do only what both its policies and the boundary allow.</p>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={!arn()}>
            Set
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** Makes a user of Cairn's own directory, and its first setup link. */
function NewDirectoryUserDialog(props: { onClose: () => void; created: (user: string, link: { url?: string | null; path: string }) => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [userName, setUserName] = createSignal("");
  const [displayName, setDisplayName] = createSignal("");
  const [givenName, setGivenName] = createSignal("");
  const [familyName, setFamilyName] = createSignal("");
  const [email, setEmail] = createSignal("");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    setError(undefined);
    try {
      const made = await api.createDirectoryUser({
        user_name: userName(),
        display_name: displayName() || userName(),
        given_name: givenName() || null,
        family_name: familyName() || null,
        email: email() || null,
      });
      const link = await api.directorySetupLink(made.id);
      toast(`Created ${userName()}`);
      dialog.close();
      props.created(userName(), link);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>New directory user</h2>
        <p class="subtle small">
          A user of Cairn's own directory, as IAM Identity Center's: they sign in with passkeys, and use the permission
          sets assigned to them. You get a setup link for their first passkey.
        </p>
        <label class="field">
          User name
          <input type="text" required maxLength={128} pattern="\S+" value={userName()} onInput={(e) => setUserName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Display name
          <input type="text" maxLength={1024} placeholder={userName()} value={displayName()} onInput={(e) => setDisplayName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Given name
          <input type="text" maxLength={1024} value={givenName()} onInput={(e) => setGivenName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Family name
          <input type="text" maxLength={1024} value={familyName()} onInput={(e) => setFamilyName(e.currentTarget.value)} />
        </label>
        <label class="field">
          E-mail
          <input type="email" maxLength={1024} value={email()} onInput={(e) => setEmail(e.currentTarget.value)} />
        </label>
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

/** Changes a user of Cairn's own directory. */
function EditDirectoryUserDialog(props: { user: DirectoryUser; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [userName, setUserName] = createSignal(props.user.user_name);
  const [displayName, setDisplayName] = createSignal(props.user.display_name);
  const [givenName, setGivenName] = createSignal(props.user.given_name ?? "");
  const [familyName, setFamilyName] = createSignal(props.user.family_name ?? "");
  const [email, setEmail] = createSignal(props.user.email ?? "");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    setError(undefined);
    try {
      await api.updateDirectoryUser(props.user.id, {
        user_name: userName(),
        display_name: displayName() || userName(),
        given_name: givenName() || null,
        family_name: familyName() || null,
        email: email() || null,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved ${userName()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          Edit <span class="mono">{props.user.user_name}</span>
        </h2>
        <label class="field">
          User name
          <input type="text" required maxLength={128} pattern="\S+" value={userName()} onInput={(e) => setUserName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Display name
          <input type="text" maxLength={1024} placeholder={userName()} value={displayName()} onInput={(e) => setDisplayName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Given name
          <input type="text" maxLength={1024} value={givenName()} onInput={(e) => setGivenName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Family name
          <input type="text" maxLength={1024} value={familyName()} onInput={(e) => setFamilyName(e.currentTarget.value)} />
        </label>
        <label class="field">
          E-mail
          <input type="email" maxLength={1024} value={email()} onInput={(e) => setEmail(e.currentTarget.value)} />
        </label>
        <p class="subtle small">Sessions already signed in keep the user name they were named after.</p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
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

/** Makes a group of Cairn's own directory, or changes one. */
function GroupDialog(props: { group?: DirectoryGroup; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal(props.group?.name ?? "");
  const [description, setDescription] = createSignal(props.group?.description ?? "");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    setError(undefined);
    try {
      if (props.group) await api.updateDirectoryGroup(props.group.id, name(), description());
      else await api.createDirectoryGroup(name(), description());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(props.group ? `Saved ${name()}` : `Made group ${name()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{props.group ? <>Edit <span class="mono">{props.group.name}</span></> : "New group"}</h2>
        <label class="field">
          Name
          <input type="text" required maxLength={1024} value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Description
          <input type="text" maxLength={1024} value={description()} onInput={(e) => setDescription(e.currentTarget.value)} />
        </label>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {props.group ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** Puts a directory user (any, an identity source's too) in a group of
 * Cairn's own directory. */
function AddMemberDialog(props: { group: DirectoryGroup; users: DirectoryUser[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const candidates = () => props.users.filter((u) => !props.group.memberships.some((m) => m.user_id === u.id));
  const [chosen, setChosen] = createSignal(candidates()[0]?.id ?? "");
  const add = async (e: SubmitEvent) => {
    e.preventDefault();
    const user = props.users.find((u) => u.id === chosen());
    if (await act(() => api.addGroupMember(props.group.id, chosen()), `Added ${user?.user_name ?? "them"} to ${props.group.name}`)) {
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
        <Show when={candidates().length} fallback={<p class="subtle">Every directory user is in it already.</p>}>
          <label class="field">
            User
            <select value={chosen()} onChange={(e) => setChosen(e.currentTarget.value)}>
              <For each={candidates()}>
                {(u) => <option value={u.id}>{`${u.display_name} (${u.user_name}, ${u.provider ?? "Cairn"})`}</option>}
              </For>
            </select>
          </label>
        </Show>
        <p class="subtle small">They get what the group's assignments give it at once.</p>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={!chosen()}>
            Add
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** A directory user's setup link for the console, shown once. */
function SetupLinkDialog(props: { user: string; url?: string | null; path: string; onClose: () => void }) {
  let dialog!: HTMLDialogElement;
  let input!: HTMLInputElement;
  onMount(() => {
    dialog.showModal();
    input.select();
  });
  const link = () => props.url ?? props.path;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(link());
      toast("Copied");
    } catch {
      input.select();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <h2>
        Setup link for <span class="mono">{props.user}</span>
      </h2>
      <p class="subtle">
        Send it to <span class="mono">{props.user}</span>: it sets up a passkey for the console, and works once, for 7
        days. A new link replaces this one.
      </p>
      <Show when={!props.url}>
        <p class="subtle small">
          This node doesn't know the console's URL (<span class="mono">--console-url</span>), so put it in front.
        </p>
      </Show>
      <div class="secret">
        <input ref={input} type="text" readOnly value={link()} />
        <button onClick={copy}>Copy</button>
      </div>
      <div class="buttons">
        <button class="primary" onClick={() => dialog.close()}>
          Done
        </button>
      </div>
    </dialog>
  );
}
