// Identity Center (see `src/identity_center.rs`): the permission sets
// directory users act with, as their roles, the assignments that give them
// to users and groups of the identity sources (set up on the Sign-in page),
// and the directory users that have signed in. The page, and a permission
// set's own page.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type Assignment, type DirectoryGroup, type DirectoryUser, type ManagedPolicy, type PermissionSet, api } from "../api";
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
        People who sign in at an identity source (set up on the <A href="/sign-in">Sign-in</A> page) are directory
        users, as in IAM Identity Center: they have no IAM user, but use the permission sets assigned to them or to
        their groups. Each permission set is a role at <span class="mono">/aws-reserved/sso.amazonaws.com/</span>, which
        only this page changes; signed in, a directory user acts as a session of its role.
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
              <Table count={d()[1].length} empty="None: no directory user can sign in yet." columns={["Permission set", "To", "Source", "Since", ""]}>
                <For each={d()[1]}>
                  {(a) => (
                    <tr>
                      <td>
                        <A class="mono" href={setHref(a.permission_set)}>
                          {a.permission_set}
                        </A>
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
                      <td class="mono small">{a.provider}</td>
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
              <Table count={d()[2].length} empty="No one has signed in at an identity source yet." columns={["Name", "Source", "Groups", "Last signed in"]}>
                <For each={d()[2]}>
                  {(u) => (
                    <tr>
                      <td>
                        {u.display_name}
                        <div class="subtle small mono">{u.user_name}</div>
                      </td>
                      <td class="mono small">{u.provider}</td>
                      <td>
                        <For each={u.groups} fallback={<span class="subtle">none</span>}>
                          {(g) => <span class="chip mono">{g}</span>}
                        </For>
                      </td>
                      <td>{ago(u.last_signed_in)}</td>
                    </tr>
                  )}
                </For>
              </Table>
              <p class="subtle small">
                Who has signed in, with their groups as their source last said. There's no directory sync: users and
                groups are here, to be assigned, once someone has signed in with them.
              </p>
            </Panel>
            <Panel title="Groups" note={`${d()[3].length}`}>
              <Table count={d()[3].length} empty="No group yet: none was in a group claim of anyone who signed in." columns={["Name", "Source", { label: "Members", num: true }]}>
                <For each={d()[3]}>
                  {(g) => (
                    <tr>
                      <td class="mono">{g.name}</td>
                      <td class="mono small">{g.provider}</td>
                      <td class="num">{g.members}</td>
                    </tr>
                  )}
                </For>
              </Table>
            </Panel>
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
      ? props.groups.map((g) => ({ id: g.id, label: `${g.name} (${g.provider})` }))
      : props.users.map((u) => ({ id: u.id, label: `${u.display_name} (${u.user_name})` }));
  const [chosen, setChosen] = createSignal("");
  const principal = () => (options().some((o) => o.id === chosen()) ? chosen() : (options()[0]?.id ?? ""));
  const [error, setError] = createSignal<string>();
  const assign = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      await api.assign(set(), kind(), principal());
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
                No {kind() === "GROUP" ? "group" : "user"} yet: users and groups are here once someone has signed in
                with them.
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
  const remove = async () => {
    if (!confirm(`Delete permission set ${name()}? Its assignments and its role go too, and with them its users' access.`)) return;
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
                <dt>Role</dt>
                <dd>
                  <A class="mono" href={roleHref(s().role_name)} title={s().role_arn}>
                    {s().role_name}
                  </A>
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
              <Table count={assignments().length} empty="None: no one uses it." columns={["To", "Source"]}>
                <For each={assignments()}>
                  {(a) => (
                    <tr>
                      <td>
                        <Show when={a.principal_type === "USER"} fallback={<><Badge>group</Badge> <span class="mono">{a.principal_name}</span></>}>
                          {a.principal_name}
                        </Show>
                      </td>
                      <td class="mono small">{a.provider}</td>
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
