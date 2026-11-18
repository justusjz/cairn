// The organization (as AWS Organizations'): the management account, which
// owns the cluster, and its member accounts, made here and closed here; its
// structure (organizational units under the root, and where each account
// is); and its service control policies, which cap what member accounts'
// principals may do.

import { A } from "@solidjs/router";
import { For, Show, createSignal, onMount } from "solid-js";
import { type OrgAccount, type OrganizationOverview, type OrgUnit, type Scp, api } from "../api";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { date } from "../format";

/** An SCP to start from, as an example to change: it denies deleting buckets. */
const SCP_EXAMPLE = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["s3:DeleteBucket"],
      "Resource": "*"
    }
  ]
}`;

/** A place in the organization: the root or a unit, with how deep it is. */
type Place = { id: string; name: string; depth: number };

/** The root, then the units under it, each under its parent, in order. */
function places(o: OrganizationOverview): Place[] {
  const out: Place[] = [{ id: o.root_id, name: "Root", depth: 0 }];
  const walk = (parent: string | null, depth: number) => {
    for (const u of o.units.filter((u) => (u.parent_id ?? null) === parent)) {
      out.push({ id: u.id, name: u.name, depth });
      walk(u.id, depth + 1);
    }
  };
  walk(null, 1);
  return out;
}

const indent = (p: Place) => `${"   ".repeat(p.depth)}${p.name}`;

export default function Organization() {
  const data = poll(() => Promise.all([api.accounts(), api.organization()]), 10000);
  const [creating, setCreating] = createSignal(false);
  const [moving, setMoving] = createSignal<OrgAccount>();
  const [unit, setUnit] = createSignal<OrgUnit | "new">();
  const [scp, setScp] = createSignal<Scp | "new">();
  const [attaching, setAttaching] = createSignal<Scp>();
  const close = async (a: OrgAccount) => {
    if (!confirm(`Close ${a.name} (${a.id})? At once: its users, roles and sessions stop working, and it can't be reopened.`)) return;
    if (await act(() => api.closeAccount(a.id), `Closed ${a.name}`)) data.refresh();
  };
  const deleteUnit = async (u: OrgUnit) => {
    if (!confirm(`Delete organizational unit ${u.name}? It must be empty: no accounts or units in it.`)) return;
    if (await act(() => api.deleteUnit(u.id), `Deleted ${u.name}`)) data.refresh();
  };
  const toggleScps = async (enabled: boolean) => {
    const ask = enabled
      ? "Disable service control policies? Every SCP is detached, and member accounts are capped by none."
      : "Enable service control policies? FullAWSAccess is attached to the root, every unit and every account, so nothing changes until you attach others.";
    if (!confirm(ask)) return;
    if (await act(() => (enabled ? api.disableScps() : api.enableScps()), enabled ? "SCPs disabled" : "SCPs enabled")) data.refresh();
  };
  const deleteScp = async (p: Scp) => {
    if (!confirm(`Delete SCP ${p.name}? It must be attached nowhere.`)) return;
    if (await act(() => api.deleteScp(p.id), `Deleted ${p.name}`)) data.refresh();
  };
  const detach = async (p: Scp, target: string, name: string) => {
    if (!confirm(`Detach ${p.name} from ${name}? It takes effect at once.`)) return;
    if (await act(() => api.detachScp(p.id, target), `Detached ${p.name} from ${name}`)) data.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Organization</h1>
        <div class="buttons">
          <button class="primary" onClick={() => setCreating(true)}>
            New account
          </button>
        </div>
      </div>
      <p class="subtle small">
        As in AWS Organizations: this account is the management account, which owns the cluster and Identity Center.
        Member accounts have their own users, roles, policies and buckets, and no root user: the management account's
        principals get in by assuming <span class="mono">OrganizationAccountAccessRole</span>, and directory users with
        the permission sets assigned to them there.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => {
          const accounts = () => d()[0];
          const o = () => d()[1];
          const placeName = (id: string | null | undefined) =>
            !id ? "Root" : (o().units.find((u) => u.id === id)?.name ?? id);
          /** A target's name: the root, a unit or an account. */
          const targetName = (id: string) =>
            id === o().root_id ? "Root" : (o().units.find((u) => u.id === id)?.name ?? accounts().find((a) => a.id === id)?.name ?? id);
          const targetsOf = (p: Scp) => o().attachments.filter((a) => a.policy_id === p.id).map((a) => a.target_id);
          return (
            <>
              <Panel title="Accounts" note={`${accounts().length}`}>
                <Table count={accounts().length} empty="None." columns={["Name", "ID", "E-mail", "In", "Joined", "Buckets", ""]}>
                  <For each={accounts()}>
                    {(a) => (
                      <tr>
                        <td>
                          {a.name}{" "}
                          <Show when={a.management}>
                            <Badge tone="ok">management</Badge>
                          </Show>
                          <Show when={a.status !== "ACTIVE"}>
                            <Badge tone="warn">{a.status.toLowerCase()}</Badge>
                          </Show>
                        </td>
                        <td class="mono small">{a.id}</td>
                        <td class="small">{a.email ?? <span class="subtle">none</span>}</td>
                        <td class="small">{placeName(a.parent_id)}</td>
                        <td>{date(a.joined_at)}</td>
                        <td class="num">{a.buckets}</td>
                        <td class="actions">
                          <Show when={a.status === "ACTIVE"}>
                            <button class="small" onClick={() => setMoving(a)}>
                              Move…
                            </button>
                          </Show>
                          <Show when={!a.management && a.status === "ACTIVE"}>
                            <A class="button small" href={`/switch-role?account=${a.id}&role=OrganizationAccountAccessRole`}>
                              Switch role
                            </A>
                          </Show>
                          <Show when={!a.management && a.status === "ACTIVE"}>
                            <button class="small danger" disabled={a.buckets > 0} title={a.buckets > 0 ? "Delete its buckets first" : ""} onClick={() => close(a)}>
                              Close
                            </button>
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </Table>
              </Panel>

              <Panel title="Organizational units" note={`${o().units.length}`}>
                <div class="buttons">
                  <button onClick={() => setUnit("new")}>New unit…</button>
                </div>
                <Table count={o().units.length + 1} columns={["Name", "ID", { label: "Accounts", num: true }, ""]}>
                  <For each={places(o())}>
                    {(p) => (
                      <tr>
                        <td class={p.depth ? "" : "subtle"}>{indent(p)}</td>
                        <td class="mono small">{p.id}</td>
                        <td class="num">
                          {accounts().filter((a) => a.status === "ACTIVE" && (a.parent_id ?? o().root_id) === p.id).length}
                        </td>
                        <td class="actions">
                          <Show when={p.depth > 0 && o().units.find((u) => u.id === p.id)}>
                            {(u) => (
                              <>
                                <button class="small" onClick={() => setUnit(u())}>
                                  Rename…
                                </button>
                                <button class="small danger" onClick={() => deleteUnit(u())}>
                                  Delete
                                </button>
                              </>
                            )}
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </Table>
                <p class="subtle small">Units nest at most five deep. Each account is in the root or one unit.</p>
              </Panel>

              <Panel title="Service control policies" note={o().scps_enabled ? "enabled" : "disabled"}>
                <div class="buttons">
                  <button onClick={() => toggleScps(o().scps_enabled)}>{o().scps_enabled ? "Disable SCPs" : "Enable SCPs"}</button>
                  <button onClick={() => setScp("new")}>New SCP…</button>
                </div>
                <p class="subtle small">
                  Once enabled, SCPs cap what member accounts' users, roles and root users may do, whatever their own
                  policies or buckets' policies allow: a request must be allowed by an SCP at every level from the root
                  down to its account, and denied by none. They grant nothing, and the management account is under
                  none. Every target keeps one SCP at least, and ten at most.
                </p>
                <Table count={o().policies.length} columns={["Name", "Attached to", ""]}>
                  <For each={o().policies}>
                    {(p) => (
                      <tr>
                        <td>
                          <span class="mono">{p.name}</span>{" "}
                          <Show when={p.aws_managed}>
                            <Badge>AWS managed</Badge>
                          </Show>
                          <Show when={p.description}>
                            <div class="subtle small">{p.description}</div>
                          </Show>
                        </td>
                        <td>
                          <For each={targetsOf(p)} fallback={<span class="subtle">nothing</span>}>
                            {(t) => (
                              <span class="chip">
                                {targetName(t)}{" "}
                                <button class="link small" title={`Detach from ${targetName(t)}`} onClick={() => detach(p, t, targetName(t))}>
                                  ×
                                </button>
                              </span>
                            )}
                          </For>
                        </td>
                        <td class="actions">
                          <Show when={o().scps_enabled}>
                            <button class="small" onClick={() => setAttaching(p)}>
                              Attach…
                            </button>
                          </Show>
                          <button class="small" onClick={() => setScp(p)}>
                            {p.aws_managed ? "View…" : "Edit…"}
                          </button>
                          <Show when={!p.aws_managed}>
                            <button class="small danger" disabled={targetsOf(p).length > 0} title={targetsOf(p).length ? "Detach it first" : ""} onClick={() => deleteScp(p)}>
                              Delete
                            </button>
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </Table>
              </Panel>

              <Show when={moving()} keyed>
                {(a) => <MoveDialog account={a} places={places(o())} onClose={() => setMoving(undefined)} changed={data.refresh} />}
              </Show>
              <Show when={unit()} keyed>
                {(u) => <UnitDialog unit={u === "new" ? undefined : u} places={places(o())} onClose={() => setUnit(undefined)} changed={data.refresh} />}
              </Show>
              <Show when={scp()} keyed>{(p) => <ScpDialog policy={p === "new" ? undefined : p} onClose={() => setScp(undefined)} changed={data.refresh} />}</Show>
              <Show when={attaching()} keyed>
                {(p) => (
                  <AttachScpDialog
                    policy={p}
                    attached={targetsOf(p)}
                    targets={[
                      ...places(o()).map((x) => ({ id: x.id, label: x.depth ? `${indent(x)} (unit)` : "Root" })),
                      ...accounts()
                        .filter((a) => a.status === "ACTIVE" && !a.management)
                        .map((a) => ({ id: a.id, label: `${a.name} (${a.id})` })),
                    ]}
                    onClose={() => setAttaching(undefined)}
                    changed={data.refresh}
                  />
                )}
              </Show>
            </>
          );
        }}
      </Show>
      <Show when={creating()}>
        <NewAccountDialog onClose={() => setCreating(false)} created={() => data.refresh()} />
      </Show>
    </>
  );
}

function NewAccountDialog(props: { onClose: () => void; created: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal("");
  const [email, setEmail] = createSignal("");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    setError(undefined);
    try {
      const made = await api.createAccount(name(), email());
      toast(`Made ${name()} (${made.id})`);
      props.created();
      dialog.close();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>New member account</h2>
        <p class="subtle small">
          It gets <span class="mono">OrganizationAccountAccessRole</span>, with full access, which this account's
          principals may assume (if their own policies allow <span class="mono">sts:AssumeRole</span>). It starts in
          the root.
        </p>
        <label class="field">
          Name
          <input type="text" required maxLength={50} value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </label>
        <label class="field">
          E-mail
          <input type="email" required minLength={6} maxLength={64} value={email()} onInput={(e) => setEmail(e.currentTarget.value)} />
        </label>
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

/** Moves an account to the root or a unit. */
function MoveDialog(props: { account: OrgAccount; places: Place[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const current = () => props.account.parent_id ?? props.places[0].id;
  const [to, setTo] = createSignal(current());
  const move = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.moveAccount(props.account.id, to()), `Moved ${props.account.name}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={move}>
        <h2>Move {props.account.name}</h2>
        <label class="field">
          To
          <select value={to()} onChange={(e) => setTo(e.currentTarget.value)}>
            <For each={props.places}>{(p) => <option value={p.id}>{indent(p)}</option>}</For>
          </select>
        </label>
        <p class="subtle small">Its principals are under the SCPs of where it goes, at once.</p>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={to() === current()}>
            Move
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** Makes an organizational unit, or renames one. */
function UnitDialog(props: { unit?: OrgUnit; places: Place[]; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const [name, setName] = createSignal(props.unit?.name ?? "");
  // Units nest at most five deep: a unit at depth 5 can't have children.
  const parents = () => props.places.filter((p) => p.depth < 5);
  const [parent, setParent] = createSignal(props.places[0].id);
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    setError(undefined);
    try {
      if (props.unit) await api.renameUnit(props.unit.id, name());
      else await api.createUnit(name(), parent());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(props.unit ? `Renamed to ${name()}` : `Made ${name()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{props.unit ? <>Rename {props.unit.name}</> : "New organizational unit"}</h2>
        <label class="field">
          Name
          <input type="text" required maxLength={128} value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </label>
        <Show when={!props.unit}>
          <label class="field">
            In
            <select value={parent()} onChange={(e) => setParent(e.currentTarget.value)}>
              <For each={parents()}>{(p) => <option value={p.id}>{indent(p)}</option>}</For>
            </select>
          </label>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {props.unit ? "Rename" : "Create"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

/** Makes a service control policy, or changes (or, AWS's, shows) one. */
function ScpDialog(props: { policy?: Scp; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  const readOnly = () => props.policy?.aws_managed ?? false;
  const [name, setName] = createSignal(props.policy?.name ?? "");
  const [description, setDescription] = createSignal(props.policy?.description ?? "");
  const [content, setContent] = createSignal(props.policy ? "" : SCP_EXAMPLE);
  const [loading, setLoading] = createSignal(!!props.policy);
  const [error, setError] = createSignal<string>();
  onMount(async () => {
    dialog.showModal();
    if (!props.policy) return;
    try {
      const doc = (await api.scp(props.policy.id)).content;
      try {
        setContent(JSON.stringify(JSON.parse(doc), null, 2));
      } catch {
        setContent(doc);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setLoading(false);
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    setError(undefined);
    const body = { name: name(), description: description(), content: content() };
    try {
      if (props.policy) await api.updateScp(props.policy.id, body);
      else await api.createScp(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(props.policy ? `Saved ${name()}` : `Made ${name()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{props.policy ? <span class="mono">{props.policy.name}</span> : "New service control policy"}</h2>
        <label class="field">
          Name
          <input type="text" required maxLength={128} disabled={readOnly()} value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </label>
        <label class="field">
          Description
          <input type="text" maxLength={512} disabled={readOnly()} value={description()} onInput={(e) => setDescription(e.currentTarget.value)} />
        </label>
        <label class="field">
          Policy
          <textarea
            class="policy"
            spellcheck={false}
            readOnly={readOnly()}
            disabled={loading()}
            value={content()}
            onInput={(e) => setContent(e.currentTarget.value)}
          />
        </label>
        <p class="subtle small">
          An identity policy's language, with a <span class="mono">Version</span> and no{" "}
          <span class="mono">Principal</span>; an Allow statement's resource is <span class="mono">*</span> only. At
          most 10,240 characters. A change takes effect at once, wherever it's attached.
        </p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            {readOnly() ? "Close" : "Cancel"}
          </button>
          <Show when={!readOnly()}>
            <button class="primary" type="submit" disabled={loading()}>
              {props.policy ? "Save" : "Create"}
            </button>
          </Show>
        </div>
      </form>
    </dialog>
  );
}

/** Attaches an SCP to the root, a unit or a member account. */
function AttachScpDialog(props: {
  policy: Scp;
  attached: string[];
  targets: { id: string; label: string }[];
  onClose: () => void;
  changed: () => void;
}) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const free = () => props.targets.filter((t) => !props.attached.includes(t.id));
  const [target, setTarget] = createSignal(free()[0]?.id ?? "");
  const attach = async (e: SubmitEvent) => {
    e.preventDefault();
    if (await act(() => api.attachScp(props.policy.id, target()), `Attached ${props.policy.name}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={attach}>
        <h2>
          Attach <span class="mono">{props.policy.name}</span>
        </h2>
        <Show when={free().length} fallback={<p class="subtle">It's attached everywhere already.</p>}>
          <label class="field">
            To
            <select value={target()} onChange={(e) => setTarget(e.currentTarget.value)}>
              <For each={free()}>{(t) => <option value={t.id}>{t.label}</option>}</For>
            </select>
          </label>
        </Show>
        <p class="subtle small">It takes effect at once, for every account at or under the target.</p>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit" disabled={!target()}>
            Attach
          </button>
        </div>
      </form>
    </dialog>
  );
}
