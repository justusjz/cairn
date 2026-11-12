import { For, Show, createSignal, onMount } from "solid-js";
import { type AccessKey, type Bucket, type Cluster, type Permission, type User, api, isOperator } from "../api";
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

export default function Users() {
  // Every few seconds: a new user's identity in the KMS comes a moment later.
  const data = poll(() => Promise.all([api.roles(), api.buckets()]), 5000);
  // The KMS is the cluster's: the operator's to set up, not a tenant's.
  const cluster = isOperator() ? poll(() => api.cluster(), 10000) : undefined;
  const kms = () => cluster?.data()?.nodes.some((n) => n.stats?.kms) ?? false;
  const [secret, setSecret] = createSignal<NewSecret>();
  const [editing, setEditing] = createSignal<{ user: string; policy?: string }>();
  const [enrollment, setEnrollment] = createSignal<{ user: string; url?: string | null; path: string }>();
  const [name, setName] = createSignal("");
  const [newSecret, setNewSecret] = createSignal("");
  const [admin, setAdmin] = createSignal(false);

  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    const res = await act(() => api.createRole(n, newSecret(), admin()), `Created user ${n}`);
    if (!res) return;
    if (!newSecret()) setSecret({ id: res.value.name, secret: res.value.secret });
    setName("");
    setNewSecret("");
    setAdmin(false);
    data.refresh();
  };

  return (
    <>
      <div class="page-head">
        <h1>{isOperator() ? "Superadmins" : "Users"}</h1>
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
          <input
            type="password"
            placeholder="secret (generated if empty)"
            aria-label="Secret"
            autocomplete="new-password"
            value={newSecret()}
            onInput={(e) => setNewSecret(e.currentTarget.value)}
          />
          <label class="check">
            <input type="checkbox" checked={admin()} onChange={(e) => setAdmin(e.currentTarget.checked)} />
            Admin
          </label>
          <button class="primary" type="submit">
            Create user
          </button>
        </form>
        <p class="subtle small">
          A new user's first access key has the user's name as its ID; a user may have {MAX_KEYS} keys, to rotate
          them. Admins have AdministratorAccess: everything in their account. Others may do what their grants (statements
          of the buckets' policies) and inline policies (IAM's policy language) allow; a Deny wins over any Allow. A user
          of the account signs in to the console through its console link.
        </p>
      </Panel>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Panel>
            <Table
              count={d()[0].length}
              empty="No users."
              columns={["Name", "Admin", "Access keys", "Grants", "Policies", "Created", ""]}
            >
              <For each={d()[0]}>
                {(user) => (
                  <UserRow
                    user={user}
                    buckets={d()[1]}
                    kms={kms()}
                    changed={data.refresh}
                    showSecret={setSecret}
                    editPolicy={(policy) => setEditing({ user: user.name, policy })}
                    showEnrollment={(e) => setEnrollment({ user: user.name, ...e })}
                  />
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={cluster?.data()}>
        {(c) => (
          <KmsPanel
            cluster={c()}
            pending={(data.data()?.[0] ?? []).filter((r) => !r.kms_entity_id).length}
            refresh={() => {
              data.refresh();
              cluster?.refresh();
            }}
          />
        )}
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

/** The KMS (OpenBao) that SSE-KMS keys are in, as each node sees it: what
 * it's to trust (Cairn's public key), whether it's reachable, and how the
 * node's logins as users went. */
function KmsPanel(props: { cluster: Cluster; pending: number; refresh: () => void }) {
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
            <Show when={props.pending}>
              <p>
                {props.pending} {props.pending === 1 ? "user has" : "users have"} no identity in OpenBao yet. Nodes log
                in for them once a minute.{" "}
                <button class="small" onClick={identify}>
                  Log in now
                </button>
              </p>
            </Show>
          </>
        )}
      </Show>
    </Panel>
  );
}

function UserRow(props: {
  user: User;
  buckets: Bucket[];
  kms: boolean;
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
        <Show
          when={r().kms_entity_id}
          fallback={
            <Show when={props.kms}>
              <div>
                <Badge tone="warn">OpenBao identity pending</Badge>
              </div>
            </Show>
          }
        >
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
        <Show when={r().keys.length} fallback={<div class="subtle">no access keys</div>}>
          <For each={r().keys}>
            {(k) => <KeyLine user={r().name} accessKey={k} changed={props.changed} showSecret={props.showSecret} />}
          </For>
        </Show>
        <button
          class="small"
          disabled={r().keys.length >= MAX_KEYS}
          title={r().keys.length >= MAX_KEYS ? `A user has at most ${MAX_KEYS}: delete one first` : ""}
          onClick={newKey}
        >
          New key
        </button>
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
        <button class="small" title="A one-time link to set up a passkey for the console" onClick={enroll}>
          Console link
        </button>
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
