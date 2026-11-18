// An account's IAM roles (see `src/roles.rs`): identities no one signs as
// with keys of their own, but assumes, as their trust policies allow, for
// temporary credentials (STS's AssumeRole; AssumeRoleWithWebIdentity, for
// the ID tokens of an OpenID Connect provider such as a CI system's or a
// Kubernetes cluster's). And those providers (see `src/iam_oidc.rs`).

import { A, useNavigate, useParams } from "@solidjs/router";
import { For, Show, createResource, createSignal, onMount } from "solid-js";
import { type IdentityProvider, type ManagedPolicy, type Role, type Tag, api, isOperator } from "../api";
import {
  AttachDialog,
  Chip,
  DetailHead,
  Gone,
  InlinePolicyDialog,
  PermissionsPanel,
  PolicyChips,
  PolicySelect,
  TagChips,
  TagRows,
  cleanTags,
  policyHref,
  roleHref,
} from "../components/Iam";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { EMPTY } from "../components/PolicyEditor";
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
  const data = poll(() => Promise.all([api.roles(), api.policies()]), 10000);
  const providers = poll(() => api.identityProviders(), 10000);
  const [creating, setCreating] = createSignal(false);
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
              columns={["Name", "Trusted by", "Permissions", { label: "Longest session", num: true }]}
            >
              <For each={d()[0]}>
                {(r) => (
                  <tr>
                    <td>
                      <A class="mono" href={roleHref(r.name)}>
                        {r.name}
                      </A>
                      <Show when={r.path !== "/"}>
                        <div class="subtle small" title={r.arn}>
                          path {r.path}
                        </div>
                      </Show>
                      <Show when={r.description}>
                        <div class="small">{r.description}</div>
                      </Show>
                      <Show when={r.boundary}>
                        {(b) => (
                          <div class="small" title={`Permissions boundary: ${b()}`}>
                            <Badge tone="warn">bounded by {b().split("/").pop()}</Badge>
                          </div>
                        )}
                      </Show>
                    </td>
                    <td>
                      <TrustChips trust={r.trust} />
                    </td>
                    <td>
                      <PolicyChips attached={r.attached} inline={r.policies} none="none: its sessions may do nothing" />
                    </td>
                    <td class="num">{duration(r.max_session_duration)}</td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <ProvidersPanel providers={providerList()} error={providers.error()} private={providers.data()?.private_issuers ?? false} changed={providers.refresh} />
      <Show when={creating()}>
        <NewRoleDialog
          policies={data.data()?.[1] ?? []}
          providers={providerList()}
          onClose={() => setCreating(false)}
          changed={data.refresh}
        />
      </Show>
    </>
  );
}

/** Who a trust policy lets in. */
function TrustChips(props: { trust: string }) {
  return (
    <For each={trusted(props.trust)} fallback={<span class="subtle">no one</span>}>
      {(t) => (
        <span class="chip" classList={{ deny: t.deny }} title={t.title}>
          {t.deny ? "denied: " : ""}
          {t.label}
        </span>
      )}
    </For>
  );
}

// ─── A role's page ───────────────────────────────────────────────────────────

export function RolePage() {
  const params = useParams();
  const navigate = useNavigate();
  const name = () => params.name!;
  const data = poll(() => Promise.all([api.roles(), api.policies(), api.buckets()]), 10000);
  const providers = poll(() => api.identityProviders().catch(() => ({ providers: [] as IdentityProvider[], private_issuers: false })), 30000);
  const role = () => data.data()?.[0].find((r) => r.name === name());
  const policies = () => data.data()?.[1] ?? [];
  const [trust, setTrust] = createSignal(false);
  const [editing, setEditing] = createSignal(false);
  const [attaching, setAttaching] = createSignal(false);
  const [inline, setInline] = createSignal<{ policy?: string }>();
  const detach = async (policy: string, arn: string) => {
    if (!confirm(`Detach ${policy} from role "${name()}"?`)) return;
    if (await act(() => api.detachFromRole(name(), arn), `Detached ${policy}`)) data.refresh();
  };
  const revoke = async () => {
    if (
      !confirm(
        `Revoke every session of role "${name()}" issued until now? Programs using them get AccessDenied, and must assume the role again.`,
      )
    )
      return;
    if (await act(() => api.revokeSessions(name()), `Revoked ${name()}'s sessions`)) data.refresh();
  };
  const blocked = () => (role()?.attached.length ?? 0) + (role()?.policies.length ?? 0) > 0;
  const remove = async () => {
    if (!confirm(`Delete role "${name()}"? Its sessions stop working.`)) return;
    if (await act(() => api.deleteRole(name()), `Deleted role ${name()}`)) navigate("/roles");
  };
  return (
    <Show when={data.data()} fallback={<Loading error={data.error()} />}>
      <Show when={role()} fallback={<Gone kind="Roles" href="/roles" name={name()} />}>
        {(r) => (
          <>
            <DetailHead kind="Roles" href="/roles" name={r().name}>
              <button title="Its description, longest session, permissions boundary and tags" onClick={() => setEditing(true)}>
                Edit…
              </button>
              <button
                title="Deny everything to the sessions issued until now (an inline policy, AWSRevokeOlderSessions), as AWS's console does"
                onClick={revoke}
              >
                Revoke sessions
              </button>
              <button
                class="danger"
                disabled={blocked()}
                title={blocked() ? "Detach its managed policies and delete its inline ones first" : ""}
                onClick={remove}
              >
                Delete
              </button>
            </DetailHead>
            <Panel title="Summary">
              <dl class="kv">
                <dt>ARN</dt>
                <dd class="mono">{r().arn}</dd>
                <dt>Description</dt>
                <dd>{r().description || <span class="subtle">none</span>}</dd>
                <dt>Path</dt>
                <dd class="mono">{r().path}</dd>
                <dt>Longest session</dt>
                <dd>{duration(r().max_session_duration)}</dd>
                <dt>Permissions boundary</dt>
                <dd>
                  <Show when={r().boundary} fallback={<span class="subtle">none</span>}>
                    {(b) => (
                      <A class="mono" href={policyHref(b())} title="Its policies allow only what this allows too">
                        {b().split("/").pop()}
                      </A>
                    )}
                  </Show>
                </dd>
                <dt>Tags</dt>
                <dd>
                  <TagChips tags={r().tags} title="A tag (aws:ResourceTag, and aws:PrincipalTag in its sessions' requests)" />
                </dd>
                <dt title="Its sessions' aws:userid is this, a colon and the session's name">ID</dt>
                <dd class="mono">{r().id}</dd>
              </dl>
            </Panel>
            <Panel title="Who may assume it">
              <TrustChips trust={r().trust} />
              <div class="pem">{pretty(r().trust)}</div>
              <div class="key-actions">
                <button class="small" onClick={() => setTrust(true)}>
                  Edit trust policy…
                </button>
              </div>
            </Panel>
            <PermissionsPanel
              attached={r().attached}
              inline={r().policies}
              none="None: its sessions may do nothing."
              detach={detach}
              editInline={(policy) => setInline({ policy })}
              attach={() => setAttaching(true)}
            />

            <Show when={trust()}>
              <TrustDialog role={r()} providers={providers.data()?.providers ?? []} onClose={() => setTrust(false)} changed={data.refresh} />
            </Show>
            <Show when={editing()}>
              <DetailsDialog role={r()} policies={policies()} onClose={() => setEditing(false)} changed={data.refresh} />
            </Show>
            <Show when={attaching()}>
              <AttachDialog
                target={r().name}
                attached={r().attached.map((a) => a.arn)}
                policies={policies()}
                attach={(arn) => api.attachToRole(r().name, arn)}
                onClose={() => setAttaching(false)}
                changed={data.refresh}
              />
            </Show>
            <Show when={inline()}>
              {(i) => (
                <InlinePolicyDialog
                  owner={`role ${r().name}`}
                  policy={i().policy}
                  buckets={(data.data()?.[2] ?? []).map((b) => b.name)}
                  load={(p) => api.rolePolicy(r().name, p)}
                  save={(p, doc) => api.putRolePolicy(r().name, p, doc)}
                  remove={(p) => api.deleteRolePolicy(r().name, p)}
                  removing={i().policy === "AWSRevokeOlderSessions" ? "The sessions it revoked work again (until they expire)." : undefined}
                  note={
                    <Show when={i().policy === "AWSRevokeOlderSessions"}>
                      <p class="subtle small">
                        This policy revokes the role's sessions issued before its time (Revoke sessions sets it). Delete it once
                        those sessions have expired.
                      </p>
                    </Show>
                  }
                  onClose={() => setInline(undefined)}
                  changed={data.refresh}
                />
              )}
            </Show>
          </>
        )}
      </Show>
    </Show>
  );
}

/** An AWS principal of a trust policy, as a chip says it: an account
 * (`arn:aws:iam::<id>:root`, which is the account, not its root user), or a
 * user or role, by name, and by its account too when that's another. */
function awsPrincipal(id: string): string {
  const account = /^\d{12}$/.test(id) ? id : id.match(/^arn:aws:iam::(\d{12}):/)?.[1];
  const own = account === accountId();
  if (/^\d{12}$/.test(id) || id.endsWith(":root")) return own ? "this account" : `account ${account}`;
  const name = id.split(":").pop() ?? id;
  return own || !account ? name : `${name} (account ${account})`;
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
            label = id === "*" ? "anyone" : awsPrincipal(id);
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
  const navigate = useNavigate();
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
    navigate(roleHref(n));
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
          <PolicySelect policies={props.policies} value={attach()} setValue={setAttach} none="No policy yet (attach or write one later)" label="Policy to attach" />
          <PolicySelect policies={props.policies} value={boundary()} setValue={setBoundary} none="No permissions boundary" label="Permissions boundary" />
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
          <PolicySelect policies={props.policies} value={boundary()} setValue={setBoundary} none="None" label="Permissions boundary" />
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
  const [adding, setAdding] = createSignal(false);
  const [editing, setEditing] = createSignal<IdentityProvider>();
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
        <div class="key-actions">
          <button class="small" onClick={() => setAdding(true)}>
            Add a provider…
          </button>
        </div>
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
                    {(r) => <Chip href={roleHref(r)}>{r}</Chip>}
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
      <Show when={adding()}>
        <NewProviderDialog onClose={() => setAdding(false)} changed={props.changed} />
      </Show>
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

/** A new OpenID Connect provider: its issuer, client IDs and thumbprints. */
function NewProviderDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [url, setUrl] = createSignal("");
  const [clientIds, setClientIds] = createSignal(STS_AUDIENCE);
  const [thumbprints, setThumbprints] = createSignal("");
  const [error, setError] = createSignal<string>();
  const add = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { url: url().trim(), client_ids: lines(clientIds()), thumbprints: lines(thumbprints()), tags: [] };
    try {
      await api.createIdentityProvider(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Added ${body.url}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={add}>
        <h2>New identity provider</h2>
        <label class="field">
          Issuer URL
          <input
            type="text"
            inputmode="url"
            placeholder="https://issuer.example.com"
            required
            value={url()}
            onInput={(e) => setUrl(e.currentTarget.value)}
          />
        </label>
        <label class="field">
          Client IDs (audiences), one a line
          <textarea rows={3} spellcheck={false} value={clientIds()} onInput={(e) => setClientIds(e.currentTarget.value)} />
        </label>
        <p class="subtle small">
          A token is taken only if it's for one of these (its aud claim); AWS's SDKs ask for{" "}
          <span class="mono">{STS_AUDIENCE}</span>.
        </p>
        <label class="field">
          Thumbprints (optional), one a line
          <textarea rows={2} spellcheck={false} value={thumbprints()} onInput={(e) => setThumbprints(e.currentTarget.value)} />
        </label>
        <p class="subtle small">
          For an issuer whose certificate isn't of a public CA: the SHA-1 of its certificate or its CA's, as{" "}
          <span class="mono">openssl x509 -fingerprint -sha1</span> shows it.
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            Add provider
          </button>
        </div>
      </form>
    </dialog>
  );
}
