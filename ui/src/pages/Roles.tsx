import { For, Show, createSignal } from "solid-js";
import { type Bucket, type Permission, type Role, api } from "../api";
import { Badge, Loading, Panel, SecretDialog, Table, act, poll } from "../components/ui";
import { date } from "../format";

const PERMISSIONS: Permission[] = ["read", "write", "delete-version"];

export default function Roles() {
  const data = poll(() => Promise.all([api.roles(), api.buckets()]));
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
                {(role) => <RoleRow role={role} buckets={d()[1]} changed={data.refresh} showSecret={setSecret} />}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={secret()}>
        {(s) => <SecretDialog name={s().name} secret={s().secret} onClose={() => setSecret(undefined)} />}
      </Show>
    </>
  );
}

function RoleRow(props: {
  role: Role;
  buckets: Bucket[];
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
      <td class="mono">{r().name}</td>
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
