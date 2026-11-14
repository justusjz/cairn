import { For, Show, createSignal, onMount } from "solid-js";
import { type AccessKey, type Cluster, type ConsoleAccess, type ManagedPolicy, type Tag, type User, api } from "../api";
import { Badge, Loading, Panel, SecretDialog, Table, act, poll, toast } from "../components/ui";
import { ago, date, pretty } from "../format";
import { EMPTY, PolicyEditor } from "../components/PolicyEditor";

/** The most access keys a user may have (as in IAM). */
const MAX_KEYS = 2;

type NewSecret = { id: string; secret: string };

/** A user's console link, to show. */
type Enrollment = { user: string; url?: string | null; path: string };

/** A person: someone who signs in to the console (or was sent a link to). */
const isPerson = (u: User) => !!u.console;

/** The account's users, people and services apart. Both are IAM users alike
 * (as in AWS); what tells them apart is how they get in: people sign in to
 * the console through a link, services sign requests with access keys.
 * Operators are users too, whose policies allow them `cairn:` actions
 * (`CairnOperatorAccess`, or `AdministratorAccess`). */
export default function Users() {
  // Every few seconds: a new user's identity in the KMS comes a moment later.
  const data = poll(() => Promise.all([api.users(), api.buckets(), api.policies()]), 5000);
  const [secret, setSecret] = createSignal<NewSecret>();
  const [editing, setEditing] = createSignal<{ user: string; policy?: string }>();
  const [attaching, setAttaching] = createSignal<User>();
  const [details, setDetails] = createSignal<User>();
  const [enrollment, setEnrollment] = createSignal<Enrollment>();
  const [name, setName] = createSignal("");
  const [kind, setKind] = createSignal<"person" | "service">("person");
  const [admin, setAdmin] = createSignal(false);
  const [path, setPath] = createSignal("");
  const [boundary, setBoundary] = createSignal("");

  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    const service = kind() === "service";
    const res = await act(
      () => api.createUser(n, { accessKey: service, admin: admin(), path: path().trim(), boundary: boundary() }),
      `Created ${n}`,
    );
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
          changed={data.refresh}
          attach={() => setAttaching(user)}
          showSecret={setSecret}
          editPolicy={(policy) => setEditing({ user: user.name, policy })}
          showEnrollment={(e) => setEnrollment({ user: user.name, ...e })}
          details={() => setDetails(user)}
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
          <input
            type="text"
            placeholder="/path/ (optional)"
            aria-label="Path"
            title="Where the user is: its ARN has the path before its name (arn:aws:iam::…:user/team/name), which policies can name"
            autocomplete="off"
            value={path()}
            onInput={(e) => setPath(e.currentTarget.value)}
          />
          <select
            aria-label="Permissions boundary"
            title="A managed policy that caps what the user's policies may allow"
            value={boundary()}
            onChange={(e) => setBoundary(e.currentTarget.value)}
          >
            <option value="">No boundary</option>
            <For each={data.data()?.[2] ?? []}>{(p) => <option value={p.arn}>Boundary: {p.name}</option>}</For>
          </select>
          <button class="primary" type="submit">
            {kind() === "person" ? "Create and get link" : "Create with access key"}
          </button>
        </form>
        <p class="subtle small">
          A person gets a one-time console link to set up a passkey (or sign in with a provider), and no access key. A
          service gets an access key, whose secret is shown once; a user may have {MAX_KEYS}, to rotate them. What a user
          may do is what its policies allow: managed ones attached to it (see Policies; an admin has AdministratorAccess,
          everything in the account), and inline ones of its own. A Deny wins over any Allow. A permissions boundary caps
          that: a user with one may do only what both its policies and the boundary allow, so a non-admin can be let make
          users only with a boundary (its condition key iam:PermissionsBoundary), under a path of theirs.
        </p>
      </Panel>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        <Panel title="People" note="sign in to the console">
          <Table
            count={count(true)}
            empty="No one yet: create a person, and send them their link."
            columns={["Name", "Sign-in", "Policies", "Created", ""]}
          >
            {rows(true)}
          </Table>
        </Panel>
        <Panel title="Service users" note="sign requests with access keys">
          <Table
            count={count(false)}
            empty="No service users."
            columns={["Name", "Access keys", "Policies", "Created", ""]}
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
            buckets={(data.data()?.[1] ?? []).map((b) => b.name)}
            onClose={() => setEditing(undefined)}
            changed={data.refresh}
          />
        )}
      </Show>
      <Show when={details()}>
        {(u) => (
          <DetailsDialog
            user={u()}
            policies={data.data()?.[2] ?? []}
            onClose={() => setDetails(undefined)}
            changed={data.refresh}
          />
        )}
      </Show>
      <Show when={attaching()}>
        {(u) => (
          <AttachDialog
            user={u()}
            policies={data.data()?.[2] ?? []}
            onClose={() => setAttaching(undefined)}
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
    await act(() => api.identifyUsers(), "Every user has its identity in OpenBao");
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
  changed: () => void;
  attach: () => void;
  showSecret: (s: NewSecret) => void;
  editPolicy: (policy?: string) => void;
  showEnrollment: (e: { url?: string | null; path: string }) => void;
  details: () => void;
}) {
  const r = () => props.user;
  const detach = async (name: string, arn: string) => {
    const admin = name === "AdministratorAccess" ? " They're no longer an admin." : "";
    if (!confirm(`Detach ${name} from "${r().name}"?${admin}`)) return;
    if (await act(() => api.detach(r().name, arn), `Detached ${name}`)) props.changed();
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
    if (!confirm(`Delete user "${r().name}", with its access keys and policies? Clients using it stop working.`))
      return;
    if (await act(() => api.deleteUser(r().name), `Deleted user ${r().name}`)) props.changed();
  };

  return (
    <tr>
      <td class="mono">
        {r().name}{" "}
        <Show when={r().admin}>
          <Badge tone="accent">admin</Badge>
        </Show>
        <Show when={r().path !== "/"}>
          <div class="subtle small" title={r().arn}>
            path {r().path}
          </div>
        </Show>
        <Show when={r().boundary}>
          {(b) => (
            <div class="small" title={`Permissions boundary: ${b()}. Its policies allow only what this allows too.`}>
              <Badge tone="warn">bounded by {b().split("/").pop()}</Badge>
            </div>
          )}
        </Show>
        <Show when={r().tags.length}>
          <div class="small">
            <For each={r().tags}>
              {(t) => (
                <span class="chip" title="A tag (aws:ResourceTag, and aws:PrincipalTag in its own requests)">
                  {t.key}={t.value}
                </span>
              )}
            </For>
          </div>
        </Show>
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
        <For each={r().attached}>
          {(a) => (
            <span class="chip" title={a.arn}>
              {a.name}
              <button title="Detach" aria-label={`Detach ${a.name}`} onClick={() => detach(a.name, a.arn)}>
                ×
              </button>
            </span>
          )}
        </For>
        <For each={r().policies}>
          {(p) => (
            <button class="chip policy" title="Its own (inline) policy: view or edit" onClick={() => props.editPolicy(p)}>
              {p}
            </button>
          )}
        </For>
        <Show when={!r().attached.length && !r().policies.length}>
          <div class="subtle">none: may do nothing</div>
        </Show>
        <div class="key-actions">
          <button class="small" onClick={props.attach}>
            Attach…
          </button>
          <button class="small" title="A policy of this user's own" onClick={() => props.editPolicy()}>
            Inline…
          </button>
        </div>
      </td>
      <td>{date(r().created_at)}</td>
      <td class="actions">
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
        <button class="small" title="Its name, path, permissions boundary and tags" onClick={props.details}>
          Details…
        </button>
        <button class="small danger" onClick={remove}>
          Delete
        </button>
      </td>
    </tr>
  );
}

/** One of a user's access keys: its ID and state, and what can be done
 * with it. The key named as the user (a migrated role's) can have its
 * secret replaced in place, as a role's could; others are rotated by making a new
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
function PolicyDialog(props: {
  user: string;
  policy?: string;
  buckets: string[];
  onClose: () => void;
  changed: () => void;
}) {
  let dialog!: HTMLDialogElement;
  const [name, setName] = createSignal(props.policy ?? "");
  const [document, setDocument] = createSignal(props.policy ? "" : EMPTY);
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
          {props.policy ? "Inline policy" : "New inline policy"} of <span class="mono">{props.user}</span>
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
        <Show when={!props.policy}>
          <p class="subtle small">
            An inline policy is this user's alone. For access others share, or that's simpler to read later, make a
            managed policy (Policies) and attach it.
          </p>
        </Show>
        <PolicyEditor document={document()} setDocument={setDocument} buckets={props.buckets} disabled={loading()} />
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


/** Attaching a managed policy to a user: those it doesn't have yet. */
function AttachDialog(props: { user: User; policies: ManagedPolicy[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const open = () => props.policies.filter((p) => !props.user.attached.some((a) => a.arn === p.arn));
  const [arn, setArn] = createSignal(open().find((p) => !p.aws)?.arn ?? open()[0]?.arn ?? "");
  const chosen = () => props.policies.find((p) => p.arn === arn());
  const attach = async (e: SubmitEvent) => {
    e.preventDefault();
    const p = chosen();
    if (!p) return;
    if (await act(() => api.attach(props.user.name, p.arn), `Attached ${p.name} to ${props.user.name}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={attach}>
        <h2>
          Attach a policy to <span class="mono">{props.user.name}</span>
        </h2>
        <Show when={open().length} fallback={<p class="subtle">Every policy is attached already.</p>}>
          <select aria-label="Policy" value={arn()} onChange={(e) => setArn(e.currentTarget.value)}>
            <optgroup label="The account's">
              <For each={open().filter((p) => !p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
            </optgroup>
            <optgroup label="Cairn's (AWS's)">
              <For each={open().filter((p) => p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
            </optgroup>
          </select>
          <Show when={chosen()}>
            {(p) => (
              <>
                <p class="subtle small">{p().description}</p>
                <div class="pem">{pretty(p().document)}</div>
              </>
            )}
          </Show>
        </Show>
        <p class="subtle small">
          To give access to a bucket that no policy covers yet, make one on the Policies page (its template writes the
          statements).
        </p>
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

/** A user's name and path (renamed or moved, as IAM's UpdateUser),
 * permissions boundary and tags. */
function DetailsDialog(props: { user: User; policies: ManagedPolicy[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal(props.user.name);
  const [path, setPath] = createSignal(props.user.path);
  const [boundary, setBoundary] = createSignal(props.user.boundary ?? "");
  const [tags, setTags] = createSignal<Tag[]>(props.user.tags.map((t) => ({ ...t })));
  const setTag = (i: number, change: Partial<Tag>) => setTags(tags().map((t, j) => (j === i ? { ...t, ...change } : t)));
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    let user = props.user.name;
    if (name().trim() !== user || path().trim() !== props.user.path) {
      const change = { name: name().trim() !== user ? name().trim() : undefined, path: path().trim() || "/" };
      if (!(await act(() => api.updateUser(user, change), `Changed ${user}`))) return;
      user = change.name ?? user;
    }
    if (boundary() !== (props.user.boundary ?? "")) {
      const done = boundary()
        ? await act(() => api.setBoundary(user, boundary()), `Set ${user}'s permissions boundary`)
        : await act(() => api.deleteBoundary(user), `Removed ${user}'s permissions boundary`);
      if (!done) return;
    }
    const wanted = tags().filter((t) => t.key.trim()).map((t) => ({ key: t.key.trim(), value: t.value }));
    if (JSON.stringify(wanted) !== JSON.stringify(props.user.tags)) {
      if (!(await act(() => api.setUserTags(user, wanted), `Set ${user}'s tags`))) return;
    }
    props.changed();
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
          <select value={boundary()} onChange={(e) => setBoundary(e.currentTarget.value)}>
            <option value="">None</option>
            <For each={props.policies}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
          </select>
        </label>
        <p class="subtle small">
          With a boundary, the user may do only what both its policies and the boundary allow (a bucket's policy that names
          the user itself still allows it).
        </p>
        <div>Tags</div>
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
