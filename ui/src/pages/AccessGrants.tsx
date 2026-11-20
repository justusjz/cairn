// S3 Access Grants (see `src/s3/access_grants`): the account's instance, its
// locations (a scope, and the role whose sessions it vends) and grants on
// them. Everything here is S3 Control's own requests, as the signed-in
// identity: what its policies allow, and `iam:PassRole` on a location's
// role.

import { For, Show, createSignal } from "solid-js";
import { type AccessGrants as Grants, api } from "../api";
import { Badge, Loading, Panel, Table, act, poll } from "../components/ui";
import { date } from "../format";

/** An ISO 8601 time, as a date like the console's others. */
const when = (iso: string) => (iso ? date(Date.parse(iso) / 1000) : "–");

export default function AccessGrants() {
  const grants = poll(() => api.accessGrants(), 10000);
  return (
    <>
      <div class="page-head">
        <h1>Access Grants</h1>
      </div>
      <p class="subtle small">
        S3 Access Grants map who may read or write which part of S3, as a list of grants rather than policies. A grantee
        calls <span class="mono">GetDataAccess</span> and gets temporary credentials of its grant's location's role,
        narrowed to what the grant allows. A location's role must allow what its grants do, and trust{" "}
        <span class="mono">access-grants.s3.amazonaws.com</span>. Tools for S3 Control work with them too (
        <span class="mono">aws s3control</span>, AWS's SDK plugins).
      </p>
      <Show when={grants.data()} fallback={<Loading error={grants.error()} />}>
        {(g) => (
          <Show
            when={g().visible}
            fallback={
              <Panel>
                <p class="subtle">You may not see the account's instance (s3:GetAccessGrantsInstance).</p>
              </Panel>
            }
          >
            <Show when={g().instance} fallback={<NoInstance changed={grants.refresh} />}>
              {(instance) => (
                <>
                  <Panel title="Instance" note="The account's one.">
                    <div class="form-row">
                      <span class="mono">{instance().arn}</span>
                      <span class="subtle small">made {when(instance().created_at)}</span>
                      <DeleteInstance grants={g()} changed={grants.refresh} />
                    </div>
                  </Panel>
                  <Locations grants={g()} changed={grants.refresh} />
                  <GrantList grants={g()} changed={grants.refresh} />
                </>
              )}
            </Show>
          </Show>
        )}
      </Show>
    </>
  );
}

function NoInstance(props: { changed: () => void }) {
  const create = async () => {
    if (await act(() => api.createAccessGrantsInstance(), "Made the instance")) props.changed();
  };
  return (
    <Panel>
      <p class="subtle">The account has no Access Grants instance yet: its locations and grants are kept in one.</p>
      <button class="primary" onClick={create}>
        Create instance
      </button>
    </Panel>
  );
}

function DeleteInstance(props: { grants: Grants; changed: () => void }) {
  const remove = async () => {
    if (!confirm("Delete the account's Access Grants instance? Only one without locations can be.")) return;
    if (await act(() => api.deleteAccessGrantsInstance(), "Deleted the instance")) props.changed();
  };
  return (
    <button class="small danger" disabled={!!props.grants.locations?.length} onClick={remove}>
      Delete instance
    </button>
  );
}

function Locations(props: { grants: Grants; changed: () => void }) {
  const [scope, setScope] = createSignal("s3://");
  const [role, setRole] = createSignal("");
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.createAccessGrantsLocation(scope().trim(), role().trim()), "Registered the location")) {
      setScope("s3://");
      setRole("");
      props.changed();
    }
  };
  const changeRole = async (id: string, current: string) => {
    const arn = prompt("The location's role (its ARN):", current);
    if (!arn || arn.trim() === current) return;
    if (await act(() => api.updateAccessGrantsLocation(id, arn.trim()), "Changed the location's role")) props.changed();
  };
  const remove = async (id: string, scope: string) => {
    if (!confirm(`Delete location ${scope}? Only one without grants can be.`)) return;
    if (await act(() => api.deleteAccessGrantsLocation(id), "Deleted the location")) props.changed();
  };
  return (
    <Panel
      title="Locations"
      note="A scope (s3://, a bucket, or a prefix), and the role whose sessions its grants vend."
    >
      <Show
        when={props.grants.locations}
        fallback={<p class="subtle">You may not list them (s3:ListAccessGrantsLocations).</p>}
      >
        {(locations) => (
          <Table count={locations().length} empty="No locations yet." columns={["Scope", "Role", "ID", "Created", ""]}>
            <For each={locations()}>
              {(l) => (
                <tr>
                  <td class="mono">{l.scope}</td>
                  <td class="mono small">{l.role_arn}</td>
                  <td class="mono small">{l.id}</td>
                  <td>{when(l.created_at)}</td>
                  <td class="num">
                    <button class="small" onClick={() => changeRole(l.id, l.role_arn)}>
                      Change role
                    </button>{" "}
                    <button class="small" onClick={() => remove(l.id, l.scope)}>
                      Delete
                    </button>
                  </td>
                </tr>
              )}
            </For>
          </Table>
        )}
      </Show>
      <form class="form-row" onSubmit={create}>
        <input
          type="text"
          placeholder="s3://bucket/prefix*"
          aria-label="Location scope"
          required
          value={scope()}
          onInput={(e) => setScope(e.currentTarget.value)}
        />
        <input
          type="text"
          placeholder="arn:aws:iam::…:role/access-grants"
          aria-label="Role ARN"
          required
          value={role()}
          onInput={(e) => setRole(e.currentTarget.value)}
        />
        <button class="primary" type="submit">
          Register location
        </button>
      </form>
    </Panel>
  );
}

function GrantList(props: { grants: Grants; changed: () => void }) {
  const [location, setLocation] = createSignal("");
  const [subPrefix, setSubPrefix] = createSignal("");
  const [object, setObject] = createSignal(false);
  const [grantee, setGrantee] = createSignal("");
  const [permission, setPermission] = createSignal("READ");
  const scopeOf = (id: string) => props.grants.locations?.find((l) => l.id === id)?.scope ?? id;
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const grant = {
      location_id: location(),
      sub_prefix: subPrefix().trim(),
      object: object(),
      grantee_type: "IAM",
      grantee: grantee().trim(),
      permission: permission(),
    };
    if (await act(() => api.createAccessGrant(grant), "Made the grant")) {
      setSubPrefix("");
      setGrantee("");
      props.changed();
    }
  };
  const remove = async (id: string, scope: string) => {
    if (!confirm(`Delete the grant on ${scope}?`)) return;
    if (await act(() => api.deleteAccessGrant(id), "Deleted the grant")) props.changed();
  };
  return (
    <Panel
      title="Grants"
      note="Each gives an IAM user or role READ, WRITE or READWRITE on a scope within its location."
    >
      <Show when={props.grants.grants} fallback={<p class="subtle">You may not list them (s3:ListAccessGrants).</p>}>
        {(grants) => (
          <Table
            count={grants().length}
            empty="No grants yet."
            columns={["Scope", "Grantee", "Permission", "Location", "Created", ""]}
          >
            <For each={grants()}>
              {(g) => (
                <tr>
                  <td class="mono">{g.scope}</td>
                  <td class="mono small">{g.grantee}</td>
                  <td>
                    <Badge tone={g.permission === "READ" ? "" : "accent"}>{g.permission}</Badge>
                  </td>
                  <td class="mono small">{scopeOf(g.location_id)}</td>
                  <td>{when(g.created_at)}</td>
                  <td class="num">
                    <button class="small" onClick={() => remove(g.id, g.scope)}>
                      Delete
                    </button>
                  </td>
                </tr>
              )}
            </For>
          </Table>
        )}
      </Show>
      <Show when={props.grants.locations?.length}>
        <form class="form-row" onSubmit={create}>
          <select
            aria-label="Location"
            required
            value={location()}
            onChange={(e) => setLocation(e.currentTarget.value)}
          >
            <option value="">location…</option>
            <For each={props.grants.locations ?? []}>{(l) => <option value={l.id}>{l.scope}</option>}</For>
          </select>
          <input
            type="text"
            placeholder="sub-prefix (all of it if empty)"
            aria-label="Sub-prefix"
            value={subPrefix()}
            onInput={(e) => setSubPrefix(e.currentTarget.value)}
          />
          <label class="check">
            <input type="checkbox" checked={object()} onChange={(e) => setObject(e.currentTarget.checked)} />
            One object
          </label>
          <input
            type="text"
            placeholder="arn:aws:iam::…:user/… or role/…"
            aria-label="Grantee"
            required
            value={grantee()}
            onInput={(e) => setGrantee(e.currentTarget.value)}
          />
          <select aria-label="Permission" value={permission()} onChange={(e) => setPermission(e.currentTarget.value)}>
            <option value="READ">READ</option>
            <option value="WRITE">WRITE</option>
            <option value="READWRITE">READWRITE</option>
          </select>
          <button class="primary" type="submit">
            Create grant
          </button>
        </form>
      </Show>
    </Panel>
  );
}
