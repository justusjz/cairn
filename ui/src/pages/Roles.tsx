import { For, Show, createSignal } from "solid-js";
import { type Bucket, type Cluster, type Permission, type Role, api } from "../api";
import { Badge, Loading, Panel, SecretDialog, Table, act, poll, toast } from "../components/ui";
import { ago, date } from "../format";

const PERMISSIONS: Permission[] = ["read", "write", "delete-version"];

export default function Roles() {
  // Every few seconds: a new role's identity in the KMS comes a moment later.
  const data = poll(() => Promise.all([api.roles(), api.buckets()]), 5000);
  const cluster = poll(() => api.cluster(), 10000);
  const kms = () => cluster.data()?.nodes.some((n) => n.stats?.kms) ?? false;
  const [secret, setSecret] = createSignal<{ name: string; secret: string }>();
  const [name, setName] = createSignal("");
  const [newSecret, setNewSecret] = createSignal("");
  const [admin, setAdmin] = createSignal(false);

  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    const res = await act(() => api.createRole(n, newSecret(), admin()), `Created role ${n}`);
    if (!res) return;
    if (!newSecret()) setSecret(res.value);
    setName("");
    setNewSecret("");
    setAdmin(false);
    data.refresh();
  };

  return (
    <>
      <div class="page-head">
        <h1>Roles</h1>
      </div>
      <Panel title="New role">
        <form class="form-row" onSubmit={create}>
          <input
            type="text"
            placeholder="role-name"
            aria-label="Role name"
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
            Create role
          </button>
        </form>
        <p class="subtle small">
          A role's name is its access key ID. Admins may create and delete buckets over S3; object access always takes a grant.
        </p>
      </Panel>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Panel>
            <Table count={d()[0].length} empty="No roles." columns={["Name", "Admin", "Grants", "Created", ""]}>
              <For each={d()[0]}>
                {(role) => (
                  <RoleRow role={role} buckets={d()[1]} kms={kms()} changed={data.refresh} showSecret={setSecret} />
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={cluster.data()}>
        {(c) => (
          <KmsPanel
            cluster={c()}
            pending={(data.data()?.[0] ?? []).filter((r) => !r.kms_entity_id).length}
            refresh={() => {
              data.refresh();
              cluster.refresh();
            }}
          />
        )}
      </Show>
      <Show when={secret()}>
        {(s) => <SecretDialog name={s().name} secret={s().secret} onClose={() => setSecret(undefined)} />}
      </Show>
    </>
  );
}

/** The KMS (OpenBao) that SSE-KMS keys are in, as each node sees it: what
 * it's to trust (Cairn's public key), whether it's reachable, and how the
 * node's logins as roles went. */
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
    await act(() => api.identifyRoles(), "Every role has its identity in OpenBao");
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
              SSE-KMS keys are in OpenBao's Transit engines. Cairn uses them as the role that asks: it logs in as each
              role through OpenBao's JWT auth method at <span class="mono">auth/{k().auth_mount}</span> (role{" "}
              <span class="mono">{k().auth_role}</span>), which is to trust this public key (
              <span class="mono">jwt_validation_pubkeys</span>). Key owners then grant keys to roles' entities.
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
                {props.pending} {props.pending === 1 ? "role has" : "roles have"} no identity in OpenBao yet. Nodes log
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

function RoleRow(props: {
  role: Role;
  buckets: Bucket[];
  kms: boolean;
  changed: () => void;
  showSecret: (s: { name: string; secret: string }) => void;
}) {
  const r = () => props.role;
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
  const rotate = async () => {
    if (!confirm(`Replace the secret of "${r().name}"? Clients using the old one stop working.`)) return;
    const res = await act(() => api.rotateSecret(r().name));
    if (res) props.showSecret(res.value);
  };
  const remove = async () => {
    if (!confirm(`Delete role "${r().name}" and all its grants? Clients using it stop working.`)) return;
    if (await act(() => api.deleteRole(r().name), `Deleted role ${r().name}`)) props.changed();
  };

  return (
    <tr>
      <td class="mono">
        {r().name}
        <div class="subtle small" title="The role's name (alias) in the KMS's auth mount for Cairn">
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
            <div class="subtle small" title="The role's identity in the KMS, which key owners grant keys to">
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
        <button class="small" onClick={rotate}>
          Rotate secret
        </button>
        <button class="small danger" onClick={remove}>
          Delete
        </button>
      </td>
    </tr>
  );
}
