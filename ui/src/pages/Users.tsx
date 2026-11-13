import { For, Show, createSignal, onMount } from "solid-js";
import { type AccessKey, type Bucket, type Cluster, type ConsoleAccess, type Permission, type User, api, isOperator } from "../api";
import { Badge, Loading, Panel, SecretDialog, Table, act, poll, toast } from "../components/ui";
import { ago, date, pretty } from "../format";

const PERMISSIONS: Permission[] = ["read", "write", "delete-version"];

/** The most access keys a user may have (as in IAM). */
const MAX_KEYS = 2;

type NewSecret = { id: string; secret: string };

/** A starting point for a new inline policy. */
const TEMPLATE = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::bucket/*"]
    }
  ]
}`;

/** A user's console link, to show. */
type Enrollment = { user: string; url?: string | null; path: string };

/** A person: someone who signs in to the console (or was sent a link to). */
const isPerson = (u: User) => !!u.console;

export default function Users() {
  return <Show when={isOperator()} fallback={<TenantUsers />}>{<Superadmins />}</Show>;
}

/** An account's users, people and services apart. Both are IAM users alike
 * (as in AWS); what tells them apart is how they get in: people sign in to
 * the console through a link, services sign requests with access keys. */
function TenantUsers() {
  // Every few seconds: a new user's identity in the KMS comes a moment later.
  const data = poll(() => Promise.all([api.roles(), api.buckets()]), 5000);
  const [secret, setSecret] = createSignal<NewSecret>();
  const [editing, setEditing] = createSignal<{ user: string; policy?: string }>();
  const [enrollment, setEnrollment] = createSignal<Enrollment>();
  const [name, setName] = createSignal("");
  const [kind, setKind] = createSignal<"person" | "service">("person");
  const [admin, setAdmin] = createSignal(false);

  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    const service = kind() === "service";
    const res = await act(() => api.createRole(n, { accessKey: service, admin: admin() }), `Created ${n}`);
    if (!res) return;
    setName("");
    setAdmin(false);
    data.refresh();
    const key = res.value.access_key;
    if (key) {
      setSecret({ id: key.name, secret: key.secret });
    } else {
      const link = await act(() => api.createEnrollment(n));
      if (link) setEnrollment({ user: n, ...link.value });
    }
  };

  const rows = (people: boolean) => (
    <For each={(data.data()?.[0] ?? []).filter((u) => isPerson(u) === people)}>
      {(user) => (
        <UserRow
          user={user}
          person={people}
          buckets={data.data()?.[1] ?? []}
          changed={data.refresh}
          showSecret={setSecret}
          editPolicy={(policy) => setEditing({ user: user.name, policy })}
          showEnrollment={(e) => setEnrollment({ user: user.name, ...e })}
        />
      )}
    </For>
  );
  const count = (people: boolean) => (data.data()?.[0] ?? []).filter((u) => isPerson(u) === people).length;

  return (
    <>
      <div class="page-head">
        <h1>Users</h1>
      </div>
      <Panel title="New user">
        <form class="form-row" onSubmit={create}>
          <input
            type="text"
            placeholder="user-name"
            aria-label="User name"
            autocomplete="off"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
          <label class="check">
            <input type="radio" name="kind" checked={kind() === "person"} onChange={() => setKind("person")} />
            Person
          </label>
          <label class="check">
            <input type="radio" name="kind" checked={kind() === "service"} onChange={() => setKind("service")} />
            Service
          </label>
          <label class="check">
            <input type="checkbox" checked={admin()} onChange={(e) => setAdmin(e.currentTarget.checked)} />
            Admin
          </label>
          <button class="primary" type="submit">
            {kind() === "person" ? "Create and get link" : "Create with access key"}
          </button>
        </form>
        <p class="subtle small">
          A person gets a one-time console link to set up a passkey (or sign in with a provider), and no access key. A
          service gets an access key, whose secret is shown once; a user may have {MAX_KEYS}, to rotate them. Admins have
          AdministratorAccess: everything in their account. Others may do what their grants (statements of the buckets'
          policies) and inline policies (IAM's policy language) allow; a Deny wins over any Allow.
        </p>
      </Panel>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        <Panel title="People" note="sign in to the console">
          <Table
            count={count(true)}
            empty="No one yet: create a person, and send them their link."
            columns={["Name", "Admin", "Sign-in", "Grants", "Policies", "Created", ""]}
          >
            {rows(true)}
          </Table>
        </Panel>
        <Panel title="Service users" note="sign requests with access keys">
          <Table
            count={count(false)}
            empty="No service users."
            columns={["Name", "Admin", "Access keys", "Grants", "Policies", "Created", ""]}
          >
            {rows(false)}
          </Table>
        </Panel>
      </Show>
      <Show when={secret()}>
        {(s) => <SecretDialog id={s().id} secret={s().secret} onClose={() => setSecret(undefined)} />}
      </Show>
      <Show when={enrollment()}>
        {(e) => <EnrollmentDialog {...e()} onClose={() => setEnrollment(undefined)} />}
      </Show>
      <Show when={editing()}>
        {(e) => (
          <PolicyDialog
            user={e().user}
            policy={e().policy}
            onClose={() => setEditing(undefined)}
            changed={data.refresh}
          />
        )}
      </Show>
    </>
  );
}

/** How a person signs in, or why they don't yet. */
function SignInCell(props: { access: ConsoleAccess }) {
  const a = () => props.access;
  const ways = () => [
    ...(a().passkeys ? [`${a().passkeys} passkey${a().passkeys === 1 ? "" : "s"}`] : []),
    ...a().providers,
  ];
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
      <div class="subtle small">
        {a().last_sign_in ? `signed in ${ago(a().last_sign_in!)}` : "never signed in"}
      </div>
    </Show>
  );
}

/** The operator account's users: the superadmins, each by being one. They
 * have no access keys, admin flag or policies, and act only in the console. */
function Superadmins() {
  const data = poll(() => api.roles(), 5000);
  const [enrollment, setEnrollment] = createSignal<Enrollment>();
  const [name, setName] = createSignal("");
  const link = async (user: string) => {
    const res = await act(() => api.createEnrollment(user));
    if (res) setEnrollment({ user, ...res.value });
  };
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    if (!(await act(() => api.createRole(n), `Added superadmin ${n}`))) return;
    setName("");
    data.refresh();
    await link(n);
  };
  const remove = async (user: string) => {
    if (!confirm(`Remove superadmin "${user}"? Their sessions as a superadmin end.`)) return;
    if (await act(() => api.deleteRole(user), `Removed ${user}`)) data.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Superadmins</h1>
        <form class="form-row" onSubmit={create}>
          <input
            type="text"
            placeholder="name"
            aria-label="Name"
            autocomplete="off"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
          <button class="primary" type="submit">
            Add superadmin
          </button>
        </form>
      </div>
      <p class="subtle small">
        Everyone in the operator account is a superadmin: they run the cluster and its accounts, and nothing in any
        tenant's. There are no permissions to set here, and no access keys: superadmins act only in the console, which
        asks for a fresh passkey to switch to this account. A new superadmin gets a one-time link to sign in.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(users) => (
          <Panel>
            <Table count={users().length} empty="No superadmins." columns={["Name", "Sign-in", "Added", ""]}>
              <For each={users()}>
                {(u) => (
                  <tr>
                    <td class="mono">{u.name}</td>
                    <td>
                      <Show when={u.console} fallback={<span class="subtle">no link sent</span>}>
                        {(c) => <SignInCell access={c()} />}
                      </Show>
                    </td>
                    <td>{date(u.created_at)}</td>
                    <td class="actions">
                      <button class="small" title="A one-time link to set up a passkey for the console" onClick={() => link(u.name)}>
                        Console link
                      </button>
                      <button class="small danger" onClick={() => remove(u.name)}>
                        Remove
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={enrollment()}>
        {(e) => <EnrollmentDialog {...e()} onClose={() => setEnrollment(undefined)} />}
      </Show>
    </>
  );
}

/** The KMS (OpenBao) that SSE-KMS keys are in, as each node sees it: what
 * it's to trust (Cairn's public key), whether it's reachable, and how the
 * node's logins as users went. The operator's: on the Storage page. */
export function KmsPanel(props: { cluster: Cluster; refresh: () => void }) {
  const nodes = () => props.cluster.nodes.filter((n) => n.stats?.kms);
  const kms = () => nodes()[0]?.stats?.kms;
  const keys = () => new Set(nodes().map((n) => n.stats?.kms?.public_key)).size;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(kms()?.public_key ?? "");
      toast("Copied");
    } catch {
      toast("Couldn't copy; select the key instead", true);
    }
  };
  const identify = async () => {
    await act(() => api.identifyRoles(), "Every user has its identity in OpenBao");
    props.refresh();
  };
  return (
    <Panel title="KMS" note={kms()?.address}>
      <Show
        when={kms()}
        fallback={
          <p class="subtle">
            No KMS is configured, so SSE-KMS requests are refused. Set <span class="mono">--kms-address</span> and{" "}
            <span class="mono">--kms-jwt-key</span> to keep keys in OpenBao.
          </p>
        }
      >
        {(k) => (
          <>
            <p class="subtle small">
              SSE-KMS keys are in OpenBao's Transit engines. Cairn uses them as the user that asks: it logs in as each
              user through OpenBao's JWT auth method at <span class="mono">auth/{k().auth_mount}</span> (role{" "}
              <span class="mono">{k().auth_role}</span>), which is to trust this public key (
              <span class="mono">jwt_validation_pubkeys</span>). Key owners then grant keys to users' entities.
            </p>
            <div class="pem">{k().public_key.trim()}</div>
            <button class="small" onClick={copy}>
              Copy public key
            </button>
            <Show when={k().sse_s3_key}>
              {(key) => (
                <p class="small">
                  SSE-S3 uses the key <span class="mono">{key()}</span> as Cairn itself, whose identity in OpenBao is{" "}
                  <Show when={k().cairn_entity} fallback={<Badge tone="warn">pending</Badge>}>
                    {(entity) => <span class="mono">{entity()}</span>}
                  </Show>
                  : grant it <span class="mono">datakey/plaintext</span> and <span class="mono">decrypt</span> on that key.
                </p>
              )}
            </Show>
            <Show when={keys() > 1}>
              <Badge tone="bad">nodes sign with different keys: give every node the same --kms-jwt-key</Badge>
            </Show>
            <Table count={nodes().length} columns={["Node", "OpenBao", "Last login"]}>
              <For each={nodes()}>
                {(n) => {
                  const s = () => n.stats!.kms!;
                  return (
                    <tr>
                      <td class="mono">#{n.id}</td>
                      <td>
                        <Show
                          when={s().reachable}
                          fallback={
                            <>
                              <Badge tone="bad">unreachable</Badge>
                              <div class="subtle small">{s().error}</div>
                            </>
                          }
                        >
                          <Show when={!s().sealed} fallback={<Badge tone="bad">sealed</Badge>}>
                            <Badge tone="ok">{s().standby ? "standby" : "active"}</Badge>
                          </Show>{" "}
                          <span class="subtle">{s().version}</span>
                        </Show>
                      </td>
                      <td>
                        <Show when={s().last_login} fallback={<span class="subtle">none since it started</span>}>
                          {(l) => (
                            <>
                              <Show when={l().error} fallback={<Badge tone="ok">ok</Badge>}>
                                <Badge tone="bad">failed</Badge>
                              </Show>{" "}
                              <span class="subtle">{ago(l().at)}</span>
                              <Show when={l().error}>{(e) => <div class="small">{e()}</div>}</Show>
                              <Show when={l().error && s().last_success}>
                                <div class="subtle small">last worked {ago(s().last_success)}</div>
                              </Show>
                            </>
                          )}
                        </Show>
                      </td>
                    </tr>
                  );
                }}
              </For>
            </Table>
            <p class="subtle small">
              Nodes log in for new users once a minute.{" "}
              <button class="small" onClick={identify}>
                Log in now
              </button>
            </p>
          </>
        )}
      </Show>
    </Panel>
  );
}

function UserRow(props: {
  user: User;
  /** Shown as a person (signs in to the console), else as a service. */
  person: boolean;
  buckets: Bucket[];
  changed: () => void;
  showSecret: (s: NewSecret) => void;
  editPolicy: (policy?: string) => void;
  showEnrollment: (e: { url?: string | null; path: string }) => void;
}) {
  const r = () => props.user;
  const [granting, setGranting] = createSignal(false);
  const [bucket, setBucket] = createSignal(props.buckets[0]?.name ?? "");
  const [perms, setPerms] = createSignal<Permission[]>(["read"]);
  const toggle = (p: Permission, on: boolean) => setPerms((ps) => (on ? [...ps, p] : ps.filter((x) => x !== p)));

  const grant = async (e: SubmitEvent) => {
    e.preventDefault();
    const ps = perms();
    if (await act(() => api.grant(r().name, bucket(), ps), `Granted ${ps.join(", ")} on ${bucket()}`)) props.changed();
  };
  const revoke = async (b: string, p: Permission) => {
    if (await act(() => api.revoke(r().name, b, p), `Revoked ${p} on ${b}`)) props.changed();
  };
  const toggleAdmin = async () => {
    if (r().admin && !confirm(`Revoke admin from "${r().name}"?`)) return;
    const msg = r().admin ? `${r().name} is no longer an admin` : `${r().name} is now an admin`;
    if (await act(() => api.setAdmin(r().name, !r().admin), msg)) props.changed();
  };
  const newKey = async () => {
    const res = await act(() => api.createKey(r().name), `Made a new access key for ${r().name}`);
    if (!res) return;
    props.showSecret(res.value);
    props.changed();
  };
  const enroll = async () => {
    const res = await act(() => api.createEnrollment(r().name));
    if (res) props.showEnrollment(res.value);
  };
  const remove = async () => {
    if (!confirm(`Delete user "${r().name}", with its access keys, grants and policies? Clients using it stop working.`))
      return;
    if (await act(() => api.deleteRole(r().name), `Deleted user ${r().name}`)) props.changed();
  };

  return (
    <tr>
      <td class="mono">
        {r().name}
        <div class="subtle small" title="The user's name (alias) in the KMS's auth mount for Cairn">
          id {r().id}
        </div>
        <Show when={r().kms_entity_id}>
          {(entity) => (
            <div class="subtle small" title="The user's identity in the KMS, which key owners grant keys to">
              KMS entity {entity()}
            </div>
          )}
        </Show>
      </td>
      <td>
        <Show when={r().admin} fallback={<span class="subtle">–</span>}>
          <Badge tone="accent">admin</Badge>
        </Show>
      </td>
      <td>
        <Show when={props.person && r().console}>{(c) => <SignInCell access={c()} />}</Show>
        <Show when={props.person && r().keys.length}>
          <div class="small" title="People sign in to the console; access keys are for programs">
            <Badge tone="warn">has access keys</Badge>
          </div>
        </Show>
        <Show
          when={r().keys.length}
          fallback={<Show when={!props.person}><div class="subtle">no access keys</div></Show>}
        >
          <For each={r().keys}>
            {(k) => <KeyLine user={r().name} accessKey={k} changed={props.changed} showSecret={props.showSecret} />}
          </For>
        </Show>
        <Show when={!props.person}>
          <button
            class="small"
            disabled={r().keys.length >= MAX_KEYS}
            title={r().keys.length >= MAX_KEYS ? `A user has at most ${MAX_KEYS}: delete one first` : ""}
            onClick={newKey}
          >
            New key
          </button>
        </Show>
      </td>
      <td>
        <Show when={r().grants.length} fallback={<span class="subtle">no grants</span>}>
          <For each={r().grants}>
            {(g) => (
              <span class="chip">
                {g.bucket}: {g.permission}
                <button title="Revoke" aria-label={`Revoke ${g.permission} on ${g.bucket}`} onClick={() => revoke(g.bucket, g.permission)}>
                  ×
                </button>
              </span>
            )}
          </For>
        </Show>
        <Show when={granting()}>
          <form class="form-row grant" onSubmit={grant}>
            <select aria-label="Bucket" value={bucket()} onChange={(e) => setBucket(e.currentTarget.value)}>
              <For each={props.buckets}>{(b) => <option value={b.name}>{b.name}</option>}</For>
            </select>
            <For each={PERMISSIONS}>
              {(p) => (
                <label class="check">
                  <input type="checkbox" checked={perms().includes(p)} onChange={(e) => toggle(p, e.currentTarget.checked)} />
                  {p}
                </label>
              )}
            </For>
            <button class="small primary" type="submit" disabled={!perms().length}>
              Grant
            </button>
          </form>
        </Show>
      </td>
      <td>
        <For each={r().policies}>
          {(p) => (
            <button class="chip policy" title="View or edit" onClick={() => props.editPolicy(p)}>
              {p}
            </button>
          )}
        </For>
        <div>
          <button class="small" onClick={() => props.editPolicy()}>
            New policy
          </button>
        </div>
      </td>
      <td>{date(r().created_at)}</td>
      <td class="actions">
        <button
          class="small"
          disabled={!props.buckets.length}
          title={props.buckets.length ? "" : "Create a bucket first"}
          onClick={() => setGranting(!granting())}
        >
          Grant…
        </button>
        <button class="small" onClick={toggleAdmin}>
          {r().admin ? "Revoke admin" : "Make admin"}
        </button>
        <button
          class="small"
          title={
            props.person
              ? "A new one-time link to set up a passkey (if they lost theirs, say)"
              : "A one-time link for a person to sign in to the console as this user"
          }
          onClick={enroll}
        >
          Console link
        </button>
        <Show when={props.person}>
          <button
            class="small"
            disabled={r().keys.length >= MAX_KEYS}
            title="An access key, for programs this person runs"
            onClick={newKey}
          >
            Access key
          </button>
        </Show>
        <button class="small danger" onClick={remove}>
          Delete
        </button>
      </td>
    </tr>
  );
}

/** One of a user's access keys: its ID and state, and what can be done
 * with it. The key named as the user (its first) can have its secret
 * replaced in place, as a role's could; others are rotated by making a new
 * key and deleting the old one. */
function KeyLine(props: {
  user: string;
  accessKey: AccessKey;
  changed: () => void;
  showSecret: (s: NewSecret) => void;
}) {
  const k = () => props.accessKey;
  const setActive = async (active: boolean) => {
    if (!active && !confirm(`Deactivate access key "${k().id}"? Clients using it stop working until it's activated.`))
      return;
    const msg = `${active ? "Activated" : "Deactivated"} access key ${k().id}`;
    if (await act(() => api.setKeyActive(props.user, k().id, active), msg)) props.changed();
  };
  const rotate = async () => {
    if (!confirm(`Replace the secret of "${k().id}"? Clients using the old one stop working.`)) return;
    const res = await act(() => api.rotateSecret(props.user));
    if (res) props.showSecret({ id: res.value.name, secret: res.value.secret });
  };
  const remove = async () => {
    if (!confirm(`Delete access key "${k().id}"? Clients using it stop working.`)) return;
    if (await act(() => api.deleteKey(props.user, k().id), `Deleted access key ${k().id}`)) props.changed();
  };
  return (
    <div class="key-line">
      <span class="mono" title={`Made ${date(k().created_at)}`}>
        {k().id}
      </span>{" "}
      <Show when={!k().active}>
        <Badge tone="warn">inactive</Badge>
      </Show>
      <div class="key-actions">
        <Show when={k().id === props.user}>
          <button class="small" onClick={rotate}>
            Replace secret
          </button>
        </Show>
        <button class="small" onClick={() => setActive(!k().active)}>
          {k().active ? "Deactivate" : "Activate"}
        </button>
        <button class="small danger" onClick={remove}>
          Delete
        </button>
      </div>
    </div>
  );
}

/** A user's inline policy, to view, edit or delete (`policy`), or a new one.
 * The server checks it as an identity policy, and says what's wrong. */
function PolicyDialog(props: { user: string; policy?: string; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  const [name, setName] = createSignal(props.policy ?? "");
  const [document, setDocument] = createSignal(props.policy ? "" : TEMPLATE);
  const [loading, setLoading] = createSignal(!!props.policy);
  const [error, setError] = createSignal<string>();
  onMount(async () => {
    dialog.showModal();
    if (!props.policy) return;
    try {
      const p = await api.policy(props.user, props.policy);
      setDocument(pretty(p.document));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setLoading(false);
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.putPolicy(props.user, n, document());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved policy ${n} of ${props.user}`);
    props.changed();
    dialog.close();
  };
  const remove = async () => {
    if (!confirm(`Delete policy "${props.policy}" of "${props.user}"?`)) return;
    if (await act(() => api.deletePolicy(props.user, props.policy!), `Deleted policy ${props.policy}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          {props.policy ? "Policy" : "New policy"} of <span class="mono">{props.user}</span>
        </h2>
        <Show when={!props.policy}>
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
        <Show when={props.policy}>
          <p class="mono">{props.policy}</p>
        </Show>
        <p class="subtle small">
          IAM's policy language, as an identity policy: no Principal; Resource names buckets
          (<span class="mono">arn:aws:s3:::bucket</span>) and objects (<span class="mono">arn:aws:s3:::bucket/key</span>).
        </p>
        <textarea
          class="policy"
          aria-label="Policy document"
          spellcheck={false}
          disabled={loading()}
          value={document()}
          onInput={(e) => setDocument(e.currentTarget.value)}
        />
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
          This node doesn't serve the console, so put the console's URL in front (as with{" "}
          <span class="mono">cairn user enroll --console-url</span>).
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
