// An account's IAM roles (see `src/roles.rs`): identities no one signs as
// with keys of their own, but assumes, as their trust policies allow, for
// temporary credentials (STS's AssumeRole; AssumeRoleWithWebIdentity, for
// the ID tokens of an OpenID Connect provider such as a CI system's or a
// Kubernetes cluster's). And those providers (see `src/iam_oidc.rs`).

import { For, Show, createResource, createSignal, onMount } from "solid-js";
import { type IdentityProvider, type ManagedPolicy, type Role, type Tag, api, isOperator } from "../api";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { EMPTY, PolicyEditor } from "../components/PolicyEditor";
import { duration, pretty } from "../format";
import { api as session } from "../session";

/** The longest session a role may allow, and the shortest (seconds). */
const MIN_SESSION = 3600;
const MAX_SESSION = 43200;

/** The audience AWS's SDKs and CI systems ask tokens for. */
const STS_AUDIENCE = "sts.amazonaws.com";

/** The account's ID, from who's signed in. */
const [me] = createResource(() => session.me().catch(() => null));
const accountId = () => me()?.identity.account_id ?? "";

export default function Roles() {
  const data = poll(() => Promise.all([api.roles(), api.policies(), api.buckets()]), 10000);
  const providers = poll(() => api.identityProviders(), 10000);
  const [creating, setCreating] = createSignal(false);
  const [trust, setTrust] = createSignal<Role>();
  const [details, setDetails] = createSignal<Role>();
  const [attaching, setAttaching] = createSignal<Role>();
  const [editing, setEditing] = createSignal<{ role: string; policy?: string }>();
  const policies = () => data.data()?.[1] ?? [];
  const buckets = () => (data.data()?.[2] ?? []).map((b) => b.name);
  const providerList = () => providers.data()?.providers ?? [];
  return (
    <>
      <div class="page-head">
        <h1>Roles</h1>
        <button class="primary" onClick={() => setCreating(true)}>
          New role
        </button>
      </div>
      <p class="subtle small">
        A role has no access keys of its own: whoever its trust policy lets in assumes it, and gets temporary
        credentials (an access key, secret and session token) that act as the role, with its policies, for up to its
        longest session. Users and other roles assume one with STS's AssumeRole (AWS CLI profiles with{" "}
        <span class="mono">role_arn</span>, Terraform's <span class="mono">assume_role</span>); programs with an ID token
        of an OpenID Connect provider below (a CI job's, a Kubernetes service account's) with AssumeRoleWithWebIdentity,
        without any secret kept in Cairn or there.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Panel>
            <Table
              count={d()[0].length}
              empty="No roles yet."
              columns={["Name", "Trusted by", "Policies", { label: "Longest session", num: true }, ""]}
            >
              <For each={d()[0]}>
                {(role) => (
                  <RoleRow
                    role={role}
                    changed={data.refresh}
                    trust={() => setTrust(role)}
                    details={() => setDetails(role)}
                    attach={() => setAttaching(role)}
                    editPolicy={(policy) => setEditing({ role: role.name, policy })}
                  />
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <ProvidersPanel providers={providerList()} error={providers.error()} private={providers.data()?.private_issuers ?? false} changed={providers.refresh} />
      <Show when={creating()}>
        <NewRoleDialog
          policies={policies()}
          providers={providerList()}
          onClose={() => setCreating(false)}
          changed={data.refresh}
        />
      </Show>
      <Show when={trust()}>
        {(r) => <TrustDialog role={r()} providers={providerList()} onClose={() => setTrust(undefined)} changed={data.refresh} />}
      </Show>
      <Show when={details()}>
        {(r) => <DetailsDialog role={r()} policies={policies()} onClose={() => setDetails(undefined)} changed={data.refresh} />}
      </Show>
      <Show when={attaching()}>
        {(r) => <AttachDialog role={r()} policies={policies()} onClose={() => setAttaching(undefined)} changed={data.refresh} />}
      </Show>
      <Show when={editing()}>
        {(e) => (
          <InlinePolicyDialog
            role={e().role}
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

/** Who a trust policy lets in, as chips: its principals, by kind. */
function trusted(trust: string): { label: string; title: string; deny: boolean }[] {
  try {
    const doc = JSON.parse(trust);
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
    const out: { label: string; title: string; deny: boolean }[] = [];
    for (const s of statements) {
      const deny = s.Effect === "Deny";
      const principal = s.Principal ?? s.NotPrincipal;
      const not = s.NotPrincipal ? "all but " : "";
      if (principal === "*") {
        out.push({ label: `${not}anyone`, title: "*", deny });
        continue;
      }
      for (const [kind, ids] of Object.entries(principal ?? {})) {
        for (const id of ([] as string[]).concat(ids as string | string[])) {
          let label = id;
          if (kind === "AWS") {
            label = id === "*" ? "anyone" : id.endsWith(":root") ? "this account" : (id.split(":").pop() ?? id);
          } else if (kind === "Federated") {
            label = `web identity: ${id.split(":oidc-provider/").pop()}`;
          }
          const conditions = s.Condition ? " (with conditions)" : "";
          out.push({ label: not + label + conditions, title: `${kind}: ${id}`, deny });
        }
      }
    }
    return out;
  } catch {
    return [];
  }
}

function RoleRow(props: {
  role: Role;
  changed: () => void;
  trust: () => void;
  details: () => void;
  attach: () => void;
  editPolicy: (policy?: string) => void;
}) {
  const r = () => props.role;
  const detach = async (name: string, arn: string) => {
    if (!confirm(`Detach ${name} from role "${r().name}"?`)) return;
    if (await act(() => api.detachFromRole(r().name, arn), `Detached ${name}`)) props.changed();
  };
  const revoke = async () => {
    if (
      !confirm(
        `Revoke every session of role "${r().name}" issued until now? Programs using them get AccessDenied, and must assume the role again.`,
      )
    )
      return;
    if (await act(() => api.revokeSessions(r().name), `Revoked ${r().name}'s sessions`)) props.changed();
  };
  const remove = async () => {
    if (!confirm(`Delete role "${r().name}"? Its sessions stop working.`)) return;
    if (await act(() => api.deleteRole(r().name), `Deleted role ${r().name}`)) props.changed();
  };
  const blocked = () => r().attached.length + r().policies.length > 0;
  return (
    <tr>
      <td>
        <span class="mono">{r().name}</span>
        <Show when={r().path !== "/"}>
          <div class="subtle small" title={r().arn}>
            path {r().path}
          </div>
        </Show>
        <Show when={r().description}>
          <div class="small">{r().description}</div>
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
                <span class="chip" title="A tag (aws:ResourceTag, and aws:PrincipalTag in its sessions' requests)">
                  {t.key}={t.value}
                </span>
              )}
            </For>
          </div>
        </Show>
        <div class="subtle small mono" title="Its unique ID; its sessions' aws:userid is this, a colon and the session's name">
          {r().id}
        </div>
      </td>
      <td>
        <For each={trusted(r().trust)} fallback={<span class="subtle">no one</span>}>
          {(t) => (
            <span class="chip" classList={{ deny: t.deny }} title={t.title}>
              {t.deny ? "denied: " : ""}
              {t.label}
            </span>
          )}
        </For>
        <div class="key-actions">
          <button class="small" onClick={props.trust}>
            Trust policy…
          </button>
        </div>
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
          <div class="subtle">none: its sessions may do nothing</div>
        </Show>
        <div class="key-actions">
          <button class="small" onClick={props.attach}>
            Attach…
          </button>
          <button class="small" title="A policy of this role's own" onClick={() => props.editPolicy()}>
            Inline…
          </button>
        </div>
      </td>
      <td class="num">{duration(r().max_session_duration)}</td>
      <td class="actions">
        <button class="small" title="Its description, longest session, permissions boundary and tags" onClick={props.details}>
          Details…
        </button>
        <button
          class="small"
          title="Deny everything to the sessions issued until now (an inline policy, AWSRevokeOlderSessions), as AWS's console does"
          onClick={revoke}
        >
          Revoke sessions
        </button>
        <button
          class="small danger"
          disabled={blocked()}
          title={blocked() ? "Detach its managed policies and delete its inline ones first" : ""}
          onClick={remove}
        >
          Delete
        </button>
      </td>
    </tr>
  );
}

// ─── Trust policies ──────────────────────────────────────────────────────────

/** A trust policy's statement, for one of the templates. */
function trustStatement(
  kind: "account" | "user" | "role" | "web",
  opts: { name?: string; provider?: IdentityProvider; audience?: string; subject?: string },
): object {
  const account = accountId();
  switch (kind) {
    case "account":
      return { Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: "sts:AssumeRole" };
    case "user":
    case "role":
      return { Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:${kind}/${opts.name}` }, Action: "sts:AssumeRole" };
    case "web": {
      const p = opts.provider!;
      const condition: Record<string, Record<string, string>> = {};
      const require = (operator: string, key: string, value: string) => ((condition[operator] ??= {})[key] = value);
      if (opts.audience) require("StringEquals", `${p.url}:aud`, opts.audience);
      if (opts.subject) require(/[*?]/.test(opts.subject) ? "StringLike" : "StringEquals", `${p.url}:sub`, opts.subject);
      return {
        Effect: "Allow",
        Principal: { Federated: p.arn },
        Action: "sts:AssumeRoleWithWebIdentity",
        ...(Object.keys(condition).length ? { Condition: condition } : {}),
      };
    }
  }
}

/** A trust policy's text, and templates that add a statement: who may
 * assume the role. */
function TrustEditor(props: { document: string; setDocument: (d: string) => void; providers: IdentityProvider[] }) {
  const [kind, setKind] = createSignal<"account" | "user" | "role" | "web">(props.providers.length ? "web" : "account");
  const [name, setName] = createSignal("");
  const [providerArn, setProviderArn] = createSignal(props.providers[0]?.arn ?? "");
  const provider = () => props.providers.find((p) => p.arn === providerArn());
  const [audience, setAudience] = createSignal(props.providers[0]?.client_ids[0] ?? STS_AUDIENCE);
  const [subject, setSubject] = createSignal("");
  const [error, setError] = createSignal<string>();
  const ready = () => (kind() === "user" || kind() === "role" ? !!name().trim() : kind() === "web" ? !!provider() : true);
  const add = () => {
    try {
      const doc = JSON.parse(props.document.trim() || EMPTY);
      const statements = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
      statements.push(trustStatement(kind(), { name: name().trim(), provider: provider(), audience: audience(), subject: subject().trim() }));
      doc.Version ??= "2012-10-17";
      doc.Statement = statements;
      props.setDocument(JSON.stringify(doc, null, 2));
      setError(undefined);
    } catch {
      setError("The document isn't valid JSON yet: fix it first, or clear it.");
    }
  };
  return (
    <>
      <div class="form-row template">
        <span class="subtle small">Let</span>
        <select aria-label="Who" value={kind()} onChange={(e) => setKind(e.currentTarget.value as "account")}>
          <option value="web" disabled={!props.providers.length}>
            web identities of a provider
          </option>
          <option value="account">this account's users and roles</option>
          <option value="user">a user</option>
          <option value="role">a role</option>
        </select>
        <Show when={kind() === "user" || kind() === "role"}>
          <input
            type="text"
            aria-label="Name"
            placeholder={kind() === "user" ? "path/user-name" : "path/role-name"}
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </Show>
        <Show when={kind() === "web"}>
          <select aria-label="Provider" value={providerArn()} onChange={(e) => {
            setProviderArn(e.currentTarget.value);
            setAudience(provider()?.client_ids[0] ?? STS_AUDIENCE);
          }}>
            <For each={props.providers}>{(p) => <option value={p.arn}>{p.url}</option>}</For>
          </select>
        </Show>
        <span class="subtle small">assume it</span>
        <button type="button" class="small" disabled={!ready()} onClick={add}>
          Add statement
        </button>
      </div>
      <Show when={kind() === "web" && provider()}>
        {(p) => (
          <div class="form-row template">
            <span class="subtle small">audience</span>
            <select aria-label="Audience" value={audience()} onChange={(e) => setAudience(e.currentTarget.value)}>
              <For each={p().client_ids}>{(c) => <option value={c}>{c}</option>}</For>
              <option value="">any of the provider's</option>
            </select>
            <span class="subtle small">subject</span>
            <input
              type="text"
              aria-label="Subject"
              placeholder="repo:my-org/my-repo:* or system:serviceaccount:ns:name"
              value={subject()}
              onInput={(e) => setSubject(e.currentTarget.value)}
            />
          </div>
        )}
      </Show>
      <Show when={kind() === "web" && !subject().trim()}>
        <p class="small warn-text">
          Without a subject, every identity the provider vouches for may assume the role (every repository of a CI
          service, say): name the subject, or a pattern of it (<span class="mono">*</span>).
        </p>
      </Show>
      <Show when={error()}>{(e) => <p class="error-text small">{e()}</p>}</Show>
      <textarea
        class="policy"
        aria-label="Trust policy"
        spellcheck={false}
        value={props.document}
        onInput={(e) => props.setDocument(e.currentTarget.value)}
      />
      <p class="subtle small">
        A trust policy names who may assume the role (Principal: <span class="mono">AWS</span> for users, roles and
        accounts; <span class="mono">Federated</span> for an OpenID Connect provider's web identities) and how (Action:
        <span class="mono"> sts:AssumeRole</span>, <span class="mono">sts:AssumeRoleWithWebIdentity</span>, and{" "}
        <span class="mono">sts:TagSession</span> for session tags). Naming the account leaves it to the users' own
        policies (they need <span class="mono">sts:AssumeRole</span> on the role); naming a user lets it in by itself. A
        web identity's token claims are condition keys: <span class="mono">&lt;provider&gt;:sub</span>,{" "}
        <span class="mono">:aud</span>, <span class="mono">:amr</span>.
      </p>
    </>
  );
}

/** A new role: its name, who may assume it, and what it may do. */
function NewRoleDialog(props: { policies: ManagedPolicy[]; providers: IdentityProvider[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal("");
  const [path, setPath] = createSignal("");
  const [description, setDescription] = createSignal("");
  const [hours, setHours] = createSignal(1);
  const [boundary, setBoundary] = createSignal("");
  const [document, setDocument] = createSignal(EMPTY);
  const [attach, setAttach] = createSignal("");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.createRole({
        name: n,
        trust: document(),
        path: path().trim(),
        description: description().trim(),
        maxSessionDuration: hours() * 3600,
        boundary: boundary(),
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Created role ${n}`);
    if (attach()) await act(() => api.attachToRole(n, attach()), `Attached ${attach().split("/").pop()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>New role</h2>
        <div class="form-row">
          <input
            type="text"
            placeholder="role-name"
            aria-label="Role name"
            autocomplete="off"
            required
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
          <input
            type="text"
            placeholder="/path/ (optional)"
            aria-label="Path"
            autocomplete="off"
            value={path()}
            onInput={(e) => setPath(e.currentTarget.value)}
          />
          <label class="check" title="The longest session it allows; a session asks for at most this (1 hour by default)">
            Longest session
            <select aria-label="Longest session" value={hours()} onChange={(e) => setHours(Number(e.currentTarget.value))}>
              <For each={[1, 2, 4, 8, 12]}>{(h) => <option value={h}>{h} h</option>}</For>
            </select>
          </label>
        </div>
        <input
          type="text"
          placeholder="Description (optional)"
          aria-label="Description"
          value={description()}
          onInput={(e) => setDescription(e.currentTarget.value)}
        />
        <h3>Who may assume it</h3>
        <TrustEditor document={document()} setDocument={setDocument} providers={props.providers} />
        <h3>What it may do</h3>
        <div class="form-row">
          <select aria-label="Policy to attach" value={attach()} onChange={(e) => setAttach(e.currentTarget.value)}>
            <option value="">No policy yet (attach or write one later)</option>
            <optgroup label="The account's">
              <For each={props.policies.filter((p) => !p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
            </optgroup>
            <optgroup label="Cairn's (AWS's)">
              <For each={props.policies.filter((p) => p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
            </optgroup>
          </select>
          <select
            aria-label="Permissions boundary"
            title="A managed policy that caps what the role's policies may allow"
            value={boundary()}
            onChange={(e) => setBoundary(e.currentTarget.value)}
          >
            <option value="">No boundary</option>
            <For each={props.policies}>{(p) => <option value={p.arn}>Boundary: {p.name}</option>}</For>
          </select>
        </div>
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

/** A role's trust policy, to change. */
function TrustDialog(props: { role: Role; providers: IdentityProvider[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [document, setDocument] = createSignal(pretty(props.role.trust));
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      await api.setTrust(props.role.name, document());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved ${props.role.name}'s trust policy`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          Who may assume <span class="mono">{props.role.name}</span>
        </h2>
        <TrustEditor document={document()} setDocument={setDocument} providers={props.providers} />
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

// ─── A role's policies and details ───────────────────────────────────────────

/** A role's inline policy, to view, edit or delete (`policy`), or a new one. */
function InlinePolicyDialog(props: { role: string; policy?: string; buckets: string[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  const [name, setName] = createSignal(props.policy ?? "");
  const [document, setDocument] = createSignal(props.policy ? "" : EMPTY);
  const [loading, setLoading] = createSignal(!!props.policy);
  const [error, setError] = createSignal<string>();
  onMount(async () => {
    dialog.showModal();
    if (!props.policy) return;
    try {
      setDocument(pretty((await api.rolePolicy(props.role, props.policy)).document));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setLoading(false);
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await api.putRolePolicy(props.role, n, document());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved policy ${n} of ${props.role}`);
    props.changed();
    dialog.close();
  };
  const remove = async () => {
    const revoking = props.policy === "AWSRevokeOlderSessions" ? " The sessions it revoked work again (until they expire)." : "";
    if (!confirm(`Delete policy "${props.policy}" of role "${props.role}"?${revoking}`)) return;
    if (await act(() => api.deleteRolePolicy(props.role, props.policy!), `Deleted policy ${props.policy}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          {props.policy ? "Inline policy" : "New inline policy"} of <span class="mono">{props.role}</span>
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
        <Show when={props.policy === "AWSRevokeOlderSessions"}>
          <p class="subtle small">
            This policy revokes the role's sessions issued before its time (Revoke sessions sets it). Delete it once those
            sessions have expired.
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

/** Attaching a managed policy to a role: those it doesn't have yet. */
function AttachDialog(props: { role: Role; policies: ManagedPolicy[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const open = () => props.policies.filter((p) => !props.role.attached.some((a) => a.arn === p.arn));
  const [arn, setArn] = createSignal(open().find((p) => !p.aws)?.arn ?? open()[0]?.arn ?? "");
  const chosen = () => props.policies.find((p) => p.arn === arn());
  const attach = async (e: SubmitEvent) => {
    e.preventDefault();
    const p = chosen();
    if (!p) return;
    if (await act(() => api.attachToRole(props.role.name, p.arn), `Attached ${p.name} to ${props.role.name}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={attach}>
        <h2>
          Attach a policy to <span class="mono">{props.role.name}</span>
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

/** Tags, as rows to edit. */
function TagRows(props: { tags: Tag[]; setTags: (t: Tag[]) => void }) {
  const set = (i: number, change: Partial<Tag>) => props.setTags(props.tags.map((t, j) => (j === i ? { ...t, ...change } : t)));
  return (
    <>
      <For each={props.tags}>
        {(t, i) => (
          <div class="form-row">
            <input type="text" placeholder="key" aria-label="Tag key" value={t.key} onInput={(e) => set(i(), { key: e.currentTarget.value })} />
            <input type="text" placeholder="value" aria-label="Tag value" value={t.value} onInput={(e) => set(i(), { value: e.currentTarget.value })} />
            <button type="button" class="small" onClick={() => props.setTags(props.tags.filter((_, j) => j !== i()))}>
              Remove
            </button>
          </div>
        )}
      </For>
      <button type="button" class="small" disabled={props.tags.length >= 50} onClick={() => props.setTags([...props.tags, { key: "", value: "" }])}>
        Add tag
      </button>
    </>
  );
}

const cleanTags = (tags: Tag[]) => tags.filter((t) => t.key.trim()).map((t) => ({ key: t.key.trim(), value: t.value }));

/** A role's description, longest session, permissions boundary and tags. */
function DetailsDialog(props: { role: Role; policies: ManagedPolicy[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const r = props.role;
  const [description, setDescription] = createSignal(r.description);
  const [hours, setHours] = createSignal(r.max_session_duration / 3600);
  const [boundary, setBoundary] = createSignal(r.boundary ?? "");
  const [tags, setTags] = createSignal<Tag[]>(r.tags.map((t) => ({ ...t })));
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const seconds = Math.round(hours() * 3600);
    if (description() !== r.description || seconds !== r.max_session_duration) {
      const change = { description: description(), maxSessionDuration: seconds };
      if (!(await act(() => api.updateRole(r.name, change), `Changed ${r.name}`))) return;
    }
    if (boundary() !== (r.boundary ?? "")) {
      const done = boundary()
        ? await act(() => api.setRoleBoundary(r.name, boundary()), `Set ${r.name}'s permissions boundary`)
        : await act(() => api.deleteRoleBoundary(r.name), `Removed ${r.name}'s permissions boundary`);
      if (!done) return;
    }
    const wanted = cleanTags(tags());
    if (JSON.stringify(wanted) !== JSON.stringify(r.tags)) {
      if (!(await act(() => api.setRoleTags(r.name, wanted), `Set ${r.name}'s tags`))) return;
    }
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          <span class="mono">{r.name}</span>
        </h2>
        <p class="subtle small mono">{r.arn}</p>
        <label class="field">
          Description
          <input type="text" value={description()} onInput={(e) => setDescription(e.currentTarget.value)} />
        </label>
        <label class="field">
          Longest session (hours)
          <input
            type="number"
            min={MIN_SESSION / 3600}
            max={MAX_SESSION / 3600}
            step="0.5"
            value={hours()}
            onInput={(e) => setHours(Number(e.currentTarget.value))}
          />
        </label>
        <p class="subtle small">
          From 1 to 12 hours. A session a role's session assumes (role chaining) lasts an hour at most, whatever this says.
        </p>
        <label class="field">
          Permissions boundary
          <select value={boundary()} onChange={(e) => setBoundary(e.currentTarget.value)}>
            <option value="">None</option>
            <For each={props.policies}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
          </select>
        </label>
        <div>Tags</div>
        <TagRows tags={tags()} setTags={setTags} />
        <p class="subtle small">
          Policies see a role's tags as aws:ResourceTag/… (in IAM actions on it) and aws:PrincipalTag/… (in its sessions'
          requests, where session tags of the same key win).
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

// ─── OpenID Connect providers ────────────────────────────────────────────────

const lines = (text: string) =>
  text
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter((l) => l);

/** The account's OpenID Connect providers: issuers whose ID tokens STS takes
 * for roles that trust them. */
function ProvidersPanel(props: { providers: IdentityProvider[]; error?: string; private: boolean; changed: () => void }) {
  const [url, setUrl] = createSignal("");
  const [clientIds, setClientIds] = createSignal(STS_AUDIENCE);
  const [thumbprint, setThumbprint] = createSignal("");
  const [editing, setEditing] = createSignal<IdentityProvider>();
  const add = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { url: url().trim(), client_ids: lines(clientIds()), thumbprints: lines(thumbprint()), tags: [] };
    if (await act(() => api.createIdentityProvider(body), `Added ${body.url}`)) {
      setUrl("");
      setThumbprint("");
      props.changed();
    }
  };
  const remove = async (p: IdentityProvider) => {
    const roles = p.roles.length ? ` Roles that trust it (${p.roles.join(", ")}) can't be assumed with its tokens any more.` : "";
    if (!confirm(`Delete the provider ${p.url}?${roles}`)) return;
    if (await act(() => api.deleteIdentityProvider(p.id), `Deleted ${p.url}`)) props.changed();
  };
  const setPrivate = async (allow: boolean) => {
    const what = allow ? "Let IAM's OIDC providers be at private addresses" : "Keep IAM's OIDC providers to public addresses";
    if (!confirm(`${what}? This is the whole cluster's setting.`)) return;
    if (await act(() => api.setSetting("oidc-private-issuers", allow ? 1 : 0), allow ? "Private issuers allowed" : "Public issuers only"))
      props.changed();
  };
  return (
    <Panel title="Identity providers" note="OpenID Connect, for AssumeRoleWithWebIdentity">
      <Show when={!props.error} fallback={<Loading error={props.error} />}>
        <p class="subtle small">
          A program with an ID token of one of these issuers (a CI job's, such as GitHub Actions'{" "}
          <span class="mono">https://token.actions.githubusercontent.com</span>; a Kubernetes service account's) assumes a
          role that trusts the provider, with no secret of Cairn's. Its token must be for one of the provider's client IDs
          (its audience; AWS's SDKs ask for <span class="mono">{STS_AUDIENCE}</span>). These are not the providers people
          sign in to the console at.
        </p>
        <form class="form-row" onSubmit={add}>
          <input
            type="text"
            inputmode="url"
            placeholder="https://issuer.example.com"
            aria-label="Issuer URL"
            required
            value={url()}
            onInput={(e) => setUrl(e.currentTarget.value)}
          />
          <input
            type="text"
            placeholder="client IDs (audiences), comma-separated"
            aria-label="Client IDs"
            value={clientIds()}
            onInput={(e) => setClientIds(e.currentTarget.value)}
          />
          <input
            type="text"
            placeholder="certificate SHA-1 (optional)"
            aria-label="Thumbprint"
            title="For an issuer whose certificate isn't of a public CA: the SHA-1 of its certificate or its CA's, as openssl x509 -fingerprint -sha1 shows it"
            value={thumbprint()}
            onInput={(e) => setThumbprint(e.currentTarget.value)}
          />
          <button class="primary" type="submit">
            Add provider
          </button>
        </form>
        <Table
          count={props.providers.length}
          empty="None: roles can be assumed with AssumeRole only."
          columns={["Issuer", "Client IDs", "Trusted by", ""]}
        >
          <For each={props.providers}>
            {(p) => (
              <tr>
                <td>
                  <span class="mono">https://{p.url}</span>
                  <div class="subtle small mono" title="What trust policies name it by (Principal: Federated)">
                    {p.arn}
                  </div>
                  <Show when={p.thumbprints.length}>
                    <div class="small" title={p.thumbprints.join("\n")}>
                      <Badge>pinned: {p.thumbprints.length} thumbprint{p.thumbprints.length === 1 ? "" : "s"}</Badge>
                    </div>
                  </Show>
                  <Show when={p.tags.length}>
                    <div class="small">
                      <For each={p.tags}>{(t) => <span class="chip">{t.key}={t.value}</span>}</For>
                    </div>
                  </Show>
                </td>
                <td>
                  <For each={p.client_ids} fallback={<Badge tone="warn">none: no token is taken</Badge>}>
                    {(c) => <span class="chip mono">{c}</span>}
                  </For>
                </td>
                <td>
                  <For each={p.roles} fallback={<span class="subtle">no role</span>}>
                    {(r) => <span class="chip mono">{r}</span>}
                  </For>
                </td>
                <td class="actions">
                  <button class="small" onClick={() => setEditing(p)}>
                    Edit…
                  </button>
                  <button class="small danger" onClick={() => remove(p)}>
                    Delete
                  </button>
                </td>
              </tr>
            )}
          </For>
        </Table>
        <p class="subtle small">
          Cairn fetches each issuer's discovery document and keys over HTTPS{" "}
          {props.private
            ? "from any address, private ones too (the cluster's oidc-private-issuers setting is on)."
            : "from public addresses only, so that no one can make it reach into its own network; an issuer inside the cluster (a Kubernetes API server's) needs the cluster's oidc-private-issuers setting."}{" "}
          <Show when={isOperator()}>
            <button class="small" onClick={() => setPrivate(!props.private)}>
              {props.private ? "Allow public issuers only" : "Allow private issuers"}
            </button>
          </Show>
        </p>
      </Show>
      <Show when={editing()}>{(p) => <ProviderDialog provider={p()} onClose={() => setEditing(undefined)} changed={props.changed} />}</Show>
    </Panel>
  );
}

/** A provider's client IDs, thumbprints and tags. */
function ProviderDialog(props: { provider: IdentityProvider; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const p = props.provider;
  const [clientIds, setClientIds] = createSignal(p.client_ids.join("\n"));
  const [thumbprints, setThumbprints] = createSignal(p.thumbprints.join("\n"));
  const [tags, setTags] = createSignal<Tag[]>(p.tags.map((t) => ({ ...t })));
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { client_ids: lines(clientIds()), thumbprints: lines(thumbprints()), tags: cleanTags(tags()) };
    if (await act(() => api.updateIdentityProvider(p.id, body), `Saved ${p.url}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          <span class="mono">https://{p.url}</span>
        </h2>
        <p class="subtle small mono">{p.arn}</p>
        <label class="field">
          Client IDs (audiences), one a line
          <textarea rows={4} spellcheck={false} value={clientIds()} onInput={(e) => setClientIds(e.currentTarget.value)} />
        </label>
        <p class="subtle small">A token is taken only if it's for one of these (its aud claim); at most 100.</p>
        <label class="field">
          Thumbprints, one a line
          <textarea rows={3} spellcheck={false} value={thumbprints()} onInput={(e) => setThumbprints(e.currentTarget.value)} />
        </label>
        <p class="subtle small">
          SHA-1s (40 hex digits) of certificates the issuer's server presents, its own or its CA's; at most 5. Needed only
          if a public CA doesn't vouch for it: then a certificate of these is trusted as its CA.
        </p>
        <div>Tags</div>
        <TagRows tags={tags()} setTags={setTags} />
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
