// An account's users: the list (people and services apart), a new user, and
// a user's own page: its details, permissions, groups, console sign-in and
// access keys.

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type AccessKey, type ConsoleAccess, type Group, type ManagedPolicy, type Tag, type User, api } from "../api";
import {
  AttachDialog,
  Checklist,
  DetailHead,
  Gone,
  InlinePolicyDialog,
  PermissionsPanel,
  PolicyChips,
  PolicySelect,
  TagChips,
  TagRows,
  cleanTags,
  groupHref,
  policyHref,
  userHref,
} from "../components/Iam";
import { Badge, Loading, Panel, SecretDialog, Table, act, poll, toast } from "../components/ui";
import { ago, date } from "../format";

/** The most access keys a user may have (as in IAM). */
const MAX_KEYS = 2;

/** The most groups a user may be in (as in IAM). */
const MAX_GROUPS = 10;

type NewSecret = { id: string; secret: string };

/** A user's console link, to show. */
type Enrollment = { user: string; url?: string | null; path: string };

/** A person: someone who signs in to the console (or was sent a link to). */
const isPerson = (u: User) => !!u.console;

/** The groups the session may list; none if it may list none. */
const listGroups = () => api.groups().catch(() => [] as Group[]);

/** The account's users, people and services apart. Both are IAM users alike
 * (as in AWS); what tells them apart is how they get in: people sign in to
 * the console through a link, services sign requests with access keys.
 * Operators are users too, whose policies allow them `cairn:` actions
 * (`CairnOperatorAccess`, or `AdministratorAccess`). */
export default function Users() {
  // Every few seconds: a new user's identity in the KMS comes a moment later.
  const data = poll(() => Promise.all([api.users(), api.policies(), listGroups()]), 5000);
  const [creating, setCreating] = createSignal(false);
  const [secret, setSecret] = createSignal<NewSecret>();
  const [enrollment, setEnrollment] = createSignal<Enrollment>();
  const users = (people: boolean) => (data.data()?.[0] ?? []).filter((u) => isPerson(u) === people);

  return (
    <>
      <div class="page-head">
        <h1>Users</h1>
        <button class="primary" onClick={() => setCreating(true)}>
          New user
        </button>
      </div>
      <p class="subtle small">
        People sign in to the console, through a one-time link that sets up a passkey; services sign requests with access
        keys. What a user may do is what its policies allow: managed ones attached to it (see Policies), inline ones of its
        own, and those of its groups (see Groups). A Deny wins over any Allow, and a permissions boundary caps it all.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        <Panel title="People" note="sign in to the console">
          <Table
            count={users(true).length}
            empty="No one yet: make a person, and send them their link."
            columns={["Name", "Sign-in", "Permissions", "Created"]}
          >
            <For each={users(true)}>{(u) => <UserRow user={u} person />}</For>
          </Table>
        </Panel>
        <Panel title="Service users" note="sign requests with access keys">
          <Table count={users(false).length} empty="No service users." columns={["Name", "Access keys", "Permissions", "Created"]}>
            <For each={users(false)}>{(u) => <UserRow user={u} person={false} />}</For>
          </Table>
        </Panel>
      </Show>
      <Show when={creating()}>
        <NewUserDialog
          policies={data.data()?.[1] ?? []}
          groups={data.data()?.[2] ?? []}
          onClose={() => setCreating(false)}
          created={(made) => {
            data.refresh();
            if ("secret" in made) setSecret(made);
            else setEnrollment(made);
          }}
        />
      </Show>
      <Show when={secret()}>{(s) => <SecretDialog id={s().id} secret={s().secret} onClose={() => setSecret(undefined)} />}</Show>
      <Show when={enrollment()}>{(e) => <EnrollmentDialog {...e()} onClose={() => setEnrollment(undefined)} />}</Show>
    </>
  );
}

/** A user in the list: who it is, how it gets in, and what it may do. */
function UserRow(props: { user: User; person: boolean }) {
  const u = () => props.user;
  return (
    <tr>
      <td>
        <A class="mono" href={userHref(u().name)}>
          {u().name}
        </A>
        <Show when={u().path !== "/"}>
          <div class="subtle small" title={u().arn}>
            path {u().path}
          </div>
        </Show>
        <Show when={u().boundary}>
          {(b) => (
            <div class="small" title={`Permissions boundary: ${b()}`}>
              <Badge tone="warn">bounded by {b().split("/").pop()}</Badge>
            </div>
          )}
        </Show>
      </td>
      <td>
        <Show
          when={props.person}
          fallback={
            <Show when={u().keys.length} fallback={<span class="subtle">none</span>}>
              {u().keys.length} ({u().keys.filter((k) => k.active).length} active)
            </Show>
          }
        >
          <Show when={u().console}>{(c) => <SignInCell access={c()} />}</Show>
        </Show>
      </td>
      <td>
        <PolicyChips attached={u().attached} inline={u().policies} groups={u().groups} none="none: may do nothing" />
      </td>
      <td>{date(u().created_at)}</td>
    </tr>
  );
}

/** How a person signs in, or why they don't yet. */
function SignInCell(props: { access: ConsoleAccess }) {
  const a = () => props.access;
  const ways = () => (a().passkeys ? [`${a().passkeys} passkey${a().passkeys === 1 ? "" : "s"}`] : []);
  return (
    <Show
      when={a().enrolled}
      fallback={
        <Show when={a().link_pending} fallback={<Badge tone="warn">link expired</Badge>}>
          <Badge tone="warn">link sent</Badge>
        </Show>
      }
    >
      <div>{ways().join(", ") || <span class="subtle">no way to sign in</span>}</div>
      <div class="subtle small">{a().last_sign_in ? `signed in ${ago(a().last_sign_in!)}` : "never signed in"}</div>
    </Show>
  );
}

/** A new user: a person (who gets a console link) or a service (an access
 * key), with the policies and groups it starts with. */
function NewUserDialog(props: {
  policies: ManagedPolicy[];
  groups: Group[];
  onClose: () => void;
  created: (made: NewSecret | Enrollment) => void;
}) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal("");
  const [kind, setKind] = createSignal<"person" | "service">("person");
  const [policies, setPolicies] = createSignal<string[]>([]);
  const [groups, setGroups] = createSignal<string[]>([]);
  const [path, setPath] = createSignal("");
  const [boundary, setBoundary] = createSignal("");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    let made;
    try {
      made = await api.createUser(n, {
        accessKey: kind() === "service",
        policies: policies(),
        groups: groups(),
        path: path().trim(),
        boundary: boundary(),
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Created ${n}`);
    dialog.close();
    if (made.access_key) {
      props.created({ id: made.access_key.name, secret: made.access_key.secret });
    } else {
      const link = await act(() => api.createEnrollment(n));
      if (link) props.created({ user: n, ...link.value });
    }
  };
  const policyItems = () =>
    [...props.policies.filter((p) => !p.aws), ...props.policies.filter((p) => p.aws)].map((p) => ({
      id: p.arn,
      label: p.name,
      note: p.aws ? "Cairn's" : p.description,
    }));
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>New user</h2>
        <input
          type="text"
          placeholder="user-name"
          aria-label="User name"
          autocomplete="off"
          required
          value={name()}
          onInput={(e) => setName(e.currentTarget.value)}
        />
        <div class="form-row">
          <label class="check">
            <input type="radio" name="kind" checked={kind() === "person"} onChange={() => setKind("person")} />
            A person, who signs in to the console
          </label>
          <label class="check">
            <input type="radio" name="kind" checked={kind() === "service"} onChange={() => setKind("service")} />
            A service, with an access key
          </label>
        </div>
        <p class="subtle small">
          {kind() === "person"
            ? "A person gets a one-time console link to set up a passkey (or sign in with a provider), and no access key."
            : `A service gets an access key, whose secret is shown once; a user may have ${MAX_KEYS}, to rotate them.`}
        </p>
        <h3>Groups</h3>
        <Checklist
          items={props.groups.map((g) => ({ id: g.name, label: g.name }))}
          chosen={groups()}
          setChosen={setGroups}
          empty="No groups (or none you may see)."
        />
        <h3>Policies</h3>
        <Checklist items={policyItems()} chosen={policies()} setChosen={setPolicies} empty="No policies." />
        <p class="subtle small">
          A user with no policy and no group may do nothing. <span class="mono">AdministratorAccess</span> is everything,
          the cluster included; <span class="mono">CairnOperatorAccess</span> the cluster without the data.
        </p>
        <h3>Where it is, and its boundary (optional)</h3>
        <div class="form-row">
          <input
            type="text"
            placeholder="/path/"
            aria-label="Path"
            title="Its ARN has the path before its name (arn:aws:iam::…:user/team/name), which policies can name"
            autocomplete="off"
            value={path()}
            onInput={(e) => setPath(e.currentTarget.value)}
          />
          <PolicySelect policies={props.policies} value={boundary()} setValue={setBoundary} none="No permissions boundary" label="Permissions boundary" />
        </div>
        <p class="subtle small">
          A permissions boundary caps what its policies allow: a delegated admin may be let make users only with one (the
          condition key iam:PermissionsBoundary), under a path of theirs.
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {kind() === "person" ? "Create and get link" : "Create with access key"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

// ─── A user's page ───────────────────────────────────────────────────────────

export function UserPage() {
  const params = useParams();
  const navigate = useNavigate();
  const name = () => params.name!;
  const data = poll(() => Promise.all([api.users(), api.policies(), api.buckets(), listGroups()]), 5000);
  const user = () => data.data()?.[0].find((u) => u.name === name());
  const policies = () => data.data()?.[1] ?? [];
  const [secret, setSecret] = createSignal<NewSecret>();
  const [enrollment, setEnrollment] = createSignal<Enrollment>();
  const [editing, setEditing] = createSignal(false);
  const [attaching, setAttaching] = createSignal(false);
  const [joining, setJoining] = createSignal(false);
  const [inline, setInline] = createSignal<{ policy?: string }>();

  const detach = async (policy: string, arn: string) => {
    if (!confirm(`Detach ${policy} from "${name()}"?`)) return;
    if (await act(() => api.detach(name(), arn), `Detached ${policy}`)) data.refresh();
  };
  const leave = async (group: string) => {
    if (!confirm(`Remove ${name()} from group "${group}"? They lose what its policies allowed them.`)) return;
    if (await act(() => api.removeFromGroup(group, name()), `Removed ${name()} from ${group}`)) data.refresh();
  };
  const newKey = async () => {
    const res = await act(() => api.createKey(name()), `Made a new access key for ${name()}`);
    if (!res) return;
    setSecret({ id: res.value.id, secret: res.value.secret });
    data.refresh();
  };
  const enroll = async () => {
    const res = await act(() => api.createEnrollment(name()));
    if (res) {
      setEnrollment({ user: name(), ...res.value });
      data.refresh();
    }
  };
  const remove = async () => {
    const groups = user()?.groups.length ? " Take it out of its groups first." : "";
    if (!confirm(`Delete user "${name()}", with its access keys and policies? Clients using it stop working.${groups}`)) return;
    if (await act(() => api.deleteUser(name()), `Deleted user ${name()}`)) navigate("/users");
  };

  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      <Show when={user()} fallback={<Gone kind="Users" href="/users" name={name()} />}>
        {(u) => (
          <>
            <DetailHead kind="Users" href="/users" name={u().name}>
              <button onClick={() => setEditing(true)}>Edit…</button>
              <button class="danger" onClick={remove}>
                Delete
              </button>
            </DetailHead>
            <Panel title="Summary">
              <dl class="kv">
                <dt>ARN</dt>
                <dd class="mono">{u().arn}</dd>
                <dt>Path</dt>
                <dd class="mono">{u().path}</dd>
                <dt>Created</dt>
                <dd>{date(u().created_at)}</dd>
                <dt>Permissions boundary</dt>
                <dd>
                  <Show when={u().boundary} fallback={<span class="subtle">none</span>}>
                    {(b) => (
                      <A class="mono" href={policyHref(b())} title="Its policies allow only what this allows too">
                        {b().split("/").pop()}
                      </A>
                    )}
                  </Show>
                </dd>
                <dt>Tags</dt>
                <dd>
                  <TagChips tags={u().tags} title="A tag (aws:ResourceTag, and aws:PrincipalTag in its own requests)" />
                </dd>
                <dt title="Its name (alias) in the KMS's auth mount for Cairn">ID</dt>
                <dd class="mono">{u().id}</dd>
                <dt title="Its identity in the KMS, which key owners grant keys to">KMS entity</dt>
                <dd class="mono">{u().kms_entity_id ?? <span class="subtle">none yet</span>}</dd>
              </dl>
            </Panel>
            <PermissionsPanel
              attached={u().attached}
              inline={u().policies}
              none={u().groups.length ? "None of its own: what its groups allow." : "None: it may do nothing."}
              detach={detach}
              editInline={(policy) => setInline({ policy })}
              attach={() => setAttaching(true)}
            />
            <Panel title="Groups" note="their policies are its own too">
              <Table count={u().groups.length} empty="In no group." columns={["Group", ""]}>
                <For each={u().groups}>
                  {(g) => (
                    <tr>
                      <td>
                        <A class="mono" href={groupHref(g)}>
                          {g}
                        </A>
                      </td>
                      <td class="actions">
                        <button class="small" onClick={() => leave(g)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </Table>
              <div class="key-actions">
                <button
                  class="small"
                  disabled={u().groups.length >= MAX_GROUPS}
                  title={u().groups.length >= MAX_GROUPS ? `A user is in at most ${MAX_GROUPS} groups` : ""}
                  onClick={() => setJoining(true)}
                >
                  Add to a group…
                </button>
              </div>
            </Panel>
            <Panel title="Console sign-in">
              <Show when={u().console} fallback={<p class="subtle">Doesn't sign in to the console: no link was ever made.</p>}>
                {(c) => <SignInCell access={c()} />}
              </Show>
              <div class="key-actions">
                <button class="small" onClick={enroll}>
                  {u().console ? "New console link" : "Console link"}
                </button>
              </div>
              <p class="subtle small">
                A one-time link to set up a passkey (for someone who lost theirs, say), valid for 24 hours; a new one
                replaces the last.
              </p>
            </Panel>
            <Panel title="Access keys" note={`${u().keys.length} of ${MAX_KEYS}`}>
              <Show when={isPerson(u()) && u().keys.length}>
                <p class="small">
                  <Badge tone="warn">a person with access keys</Badge>{" "}
                  <span class="subtle">People sign in to the console; access keys are for programs.</span>
                </p>
              </Show>
              <Table count={u().keys.length} empty="No access keys." columns={["Access key ID", "State", "Made", ""]}>
                <For each={u().keys}>{(k) => <KeyRow user={u().name} accessKey={k} changed={data.refresh} />}</For>
              </Table>
              <div class="key-actions">
                <button
                  class="small"
                  disabled={u().keys.length >= MAX_KEYS}
                  title={u().keys.length >= MAX_KEYS ? `A user has at most ${MAX_KEYS}: delete one first` : ""}
                  onClick={newKey}
                >
                  New access key
                </button>
              </div>
              <p class="subtle small">
                A key's secret is shown once, when it's made, and never changes: rotate a key by making a new one, moving its
                clients over, and deleting the old one.
              </p>
            </Panel>

            <Show when={editing()}>
              <EditUserDialog
                user={u()}
                policies={policies()}
                onClose={() => setEditing(false)}
                changed={(renamed) => {
                  if (renamed) navigate(userHref(renamed), { replace: true });
                  data.refresh();
                }}
              />
            </Show>
            <Show when={attaching()}>
              <AttachDialog
                target={u().name}
                attached={u().attached.map((a) => a.arn)}
                policies={policies()}
                attach={(arn) => api.attach(u().name, arn)}
                onClose={() => setAttaching(false)}
                changed={data.refresh}
              />
            </Show>
            <Show when={joining()}>
              <JoinGroupDialog
                user={u().name}
                groups={(data.data()?.[3] ?? []).map((g) => g.name).filter((g) => !u().groups.includes(g))}
                onClose={() => setJoining(false)}
                changed={data.refresh}
              />
            </Show>
            <Show when={inline()}>
              {(i) => (
                <InlinePolicyDialog
                  owner={u().name}
                  policy={i().policy}
                  buckets={(data.data()?.[2] ?? []).map((b) => b.name)}
                  load={(p) => api.policy(u().name, p)}
                  save={(p, doc) => api.putPolicy(u().name, p, doc)}
                  remove={(p) => api.deletePolicy(u().name, p)}
                  onClose={() => setInline(undefined)}
                  changed={data.refresh}
                />
              )}
            </Show>
            <Show when={secret()}>{(s) => <SecretDialog id={s().id} secret={s().secret} onClose={() => setSecret(undefined)} />}</Show>
            <Show when={enrollment()}>{(e) => <EnrollmentDialog {...e()} onClose={() => setEnrollment(undefined)} />}</Show>
          </>
        )}
      </Show>
    </Show>
  );
}

/** One of a user's access keys: its ID and state, and what can be done
 * with it. */
function KeyRow(props: { user: string; accessKey: AccessKey; changed: () => void }) {
  const k = () => props.accessKey;
  const setActive = async (active: boolean) => {
    if (!active && !confirm(`Deactivate access key "${k().id}"? Clients using it stop working until it's activated.`)) return;
    const msg = `${active ? "Activated" : "Deactivated"} access key ${k().id}`;
    if (await act(() => api.setKeyActive(props.user, k().id, active), msg)) props.changed();
  };
  const remove = async () => {
    if (!confirm(`Delete access key "${k().id}"? Clients using it stop working.`)) return;
    if (await act(() => api.deleteKey(props.user, k().id), `Deleted access key ${k().id}`)) props.changed();
  };
  return (
    <tr>
      <td class="mono">{k().id}</td>
      <td>
        <Show when={k().active} fallback={<Badge tone="warn">inactive</Badge>}>
          <Badge tone="ok">active</Badge>
        </Show>
      </td>
      <td>{date(k().created_at)}</td>
      <td class="actions">
        <button class="small" onClick={() => setActive(!k().active)}>
          {k().active ? "Deactivate" : "Activate"}
        </button>
        <button class="small danger" onClick={remove}>
          Delete
        </button>
      </td>
    </tr>
  );
}

/** Adding a user to a group it isn't in. */
function JoinGroupDialog(props: { user: string; groups: string[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [group, setGroup] = createSignal(props.groups[0] ?? "");
  const join = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.addToGroup(group(), props.user), `Added ${props.user} to ${group()}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={join}>
        <h2>
          Add <span class="mono">{props.user}</span> to a group
        </h2>
        <Show when={props.groups.length} fallback={<p class="subtle">It's in every group you may see.</p>}>
          <select aria-label="Group" value={group()} onChange={(e) => setGroup(e.currentTarget.value)}>
            <For each={props.groups}>{(g) => <option value={g}>{g}</option>}</For>
          </select>
        </Show>
        <p class="subtle small">They get what the group's policies allow, as long as they're in it.</p>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={!group()}>
            Add
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** A user's name and path (renamed or moved, as IAM's UpdateUser),
 * permissions boundary and tags. `changed` gets its new name if renamed. */
function EditUserDialog(props: { user: User; policies: ManagedPolicy[]; onClose: () => void; changed: (renamed?: string) => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal(props.user.name);
  const [path, setPath] = createSignal(props.user.path);
  const [boundary, setBoundary] = createSignal(props.user.boundary ?? "");
  const [tags, setTags] = createSignal<Tag[]>(props.user.tags.map((t) => ({ ...t })));
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    let user = props.user.name;
    let renamed: string | undefined;
    if (name().trim() !== user || path().trim() !== props.user.path) {
      const change = { name: name().trim() !== user ? name().trim() : undefined, path: path().trim() || "/" };
      if (!(await act(() => api.updateUser(user, change), `Changed ${user}`))) return;
      renamed = change.name;
      user = change.name ?? user;
    }
    if (boundary() !== (props.user.boundary ?? "")) {
      const done = boundary()
        ? await act(() => api.setBoundary(user, boundary()), `Set ${user}'s permissions boundary`)
        : await act(() => api.deleteBoundary(user), `Removed ${user}'s permissions boundary`);
      if (!done) return props.changed(renamed);
    }
    const wanted = cleanTags(tags());
    if (JSON.stringify(wanted) !== JSON.stringify(props.user.tags)) {
      if (!(await act(() => api.setUserTags(user, wanted), `Set ${user}'s tags`))) return props.changed(renamed);
    }
    props.changed(renamed);
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          <span class="mono">{props.user.name}</span>
        </h2>
        <p class="subtle small mono">{props.user.arn}</p>
        <label class="field">
          Name
          <input type="text" autocomplete="off" value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Path
          <input type="text" autocomplete="off" value={path()} onInput={(e) => setPath(e.currentTarget.value)} />
        </label>
        <p class="subtle small">
          Renaming or moving a user changes its ARN: policies that name it by its ARN (but buckets' policies, which keep
          naming it) need changing too.
        </p>
        <label class="field">
          Permissions boundary
          <PolicySelect policies={props.policies} value={boundary()} setValue={setBoundary} none="None" label="Permissions boundary" />
        </label>
        <p class="subtle small">
          With a boundary, the user may do only what both its policies and the boundary allow (a bucket's policy that names
          the user itself still allows it).
        </p>
        <div>Tags</div>
        <TagRows tags={tags()} setTags={setTags} />
        <p class="subtle small">
          Policies see a user's tags as aws:ResourceTag/… (in IAM actions on it) and aws:PrincipalTag/… (in its own
          requests). Keys are unique regardless of case.
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

/** A user's enrollment link for the console, shown once. */
export function EnrollmentDialog(props: { user: string; url?: string | null; path: string; onClose: () => void }) {
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
        Console link for <span class="mono">{props.user}</span>
      </h2>
      <p class="subtle">
        Send it to <span class="mono">{props.user}</span>: it sets up a passkey for the console, and works once, for 24
        hours. A new link replaces this one.
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
