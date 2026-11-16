// What the IAM pages share: links between users, groups, roles and
// policies, an identity's permissions (attached, inline, and a user's
// groups'), attaching a managed policy, an inline policy's editor, and tags.

import { A } from "@solidjs/router";
import { For, type JSX, Show, createSignal, onMount } from "solid-js";
import { type ManagedPolicy, type Tag } from "../api";
import { pretty } from "../format";
import { EMPTY, PolicyEditor } from "./PolicyEditor";
import { Panel, Table, act, toast } from "./ui";

/** Whether `arn` is one of Cairn's (AWS's) managed policies. */
export const isAws = (arn: string) => arn.startsWith("arn:aws:iam::aws:");

const at = (kind: string, name: string) => `/${kind}/${encodeURIComponent(name)}`;
export const userHref = (name: string) => at("users", name);
export const groupHref = (name: string) => at("groups", name);
export const roleHref = (name: string) => at("roles", name);
/** A managed policy's page, by its ARN: Cairn's and the account's may share
 * a name. */
export const policyHref = (arn: string) => at("policies", arn.split("/").pop()!) + (isAws(arn) ? "?aws" : "");

/** A link to a user, group, role or managed policy, as a chip. */
export function Chip(props: { href: string; title?: string; children: JSX.Element }) {
  return (
    <A class="chip link mono" href={props.href} title={props.title}>
      {props.children}
    </A>
  );
}

/** The back link above a detail page, and its title. */
export function DetailHead(props: { kind: string; href: string; name: string; children?: JSX.Element }) {
  return (
    <>
      <div class="crumbs">
        <A href={props.href}>{props.kind}</A>
        <span class="sep">/</span>
        <span class="mono">{props.name}</span>
      </div>
      <div class="page-head">
        <h1>{props.name}</h1>
        <div class="buttons">{props.children}</div>
      </div>
    </>
  );
}

/** A detail page's subject, gone (deleted, or renamed elsewhere). */
export function Gone(props: { kind: string; href: string; name: string }) {
  return (
    <>
      <DetailHead kind={props.kind} href={props.href} name={props.name} />
      <Panel>
        <p class="subtle">
          There's no {props.kind.toLowerCase().replace(/s$/, "")} named <span class="mono">{props.name}</span> (or you
          may not see it). <A href={props.href}>Back to {props.kind.toLowerCase()}</A>
        </p>
      </Panel>
    </>
  );
}

/** Managed policies, attached and inline ones, as links: what a list row
 * shows. */
export function PolicyChips(props: { attached: { name: string; arn: string }[]; inline: string[]; groups?: string[]; none: string }) {
  return (
    <>
      <For each={props.attached}>{(a) => <Chip href={policyHref(a.arn)} title={a.arn}>{a.name}</Chip>}</For>
      <For each={props.inline}>
        {(p) => (
          <span class="chip mono" title="An inline policy: on the detail page">
            {p} <span class="subtle">inline</span>
          </span>
        )}
      </For>
      <For each={props.groups ?? []}>
        {(g) => (
          <Chip href={groupHref(g)} title={`In group ${g}: its policies are this user's too`}>
            group {g}
          </Chip>
        )}
      </For>
      <Show when={!props.attached.length && !props.inline.length && !props.groups?.length}>
        <span class="subtle">{props.none}</span>
      </Show>
    </>
  );
}

/** An identity's (a user's, group's or role's) policies, attached and
 * inline, each to open, detach or delete; and attaching or writing one. */
export function PermissionsPanel(props: {
  attached: { name: string; arn: string }[];
  inline: string[];
  none: string;
  detach: (name: string, arn: string) => void;
  editInline: (name?: string) => void;
  attach: () => void;
  note?: JSX.Element;
}) {
  return (
    <Panel title="Permissions">
      <Table count={props.attached.length + props.inline.length} empty={props.none} columns={["Policy", "Type", ""]}>
        <For each={props.attached}>
          {(a) => (
            <tr>
              <td>
                <A class="mono" href={policyHref(a.arn)} title={a.arn}>
                  {a.name}
                </A>
              </td>
              <td class="subtle">{isAws(a.arn) ? "managed (Cairn's)" : "managed"}</td>
              <td class="actions">
                <button class="small" onClick={() => props.detach(a.name, a.arn)}>
                  Detach
                </button>
              </td>
            </tr>
          )}
        </For>
        <For each={props.inline}>
          {(p) => (
            <tr>
              <td>
                <button class="link mono" onClick={() => props.editInline(p)}>
                  {p}
                </button>
              </td>
              <td class="subtle">inline</td>
              <td class="actions">
                <button class="small" onClick={() => props.editInline(p)}>
                  Edit…
                </button>
              </td>
            </tr>
          )}
        </For>
      </Table>
      <div class="key-actions">
        <button class="small" onClick={props.attach}>
          Attach a policy…
        </button>
        <button class="small" title="A policy of its own, which nothing else shares" onClick={() => props.editInline()}>
          New inline policy…
        </button>
      </div>
      {props.note}
    </Panel>
  );
}

/** Managed policies to pick from: the account's, then Cairn's. */
export function PolicySelect(props: { policies: ManagedPolicy[]; value: string; setValue: (arn: string) => void; none?: string; label?: string }) {
  return (
    <select aria-label={props.label ?? "Policy"} value={props.value} onChange={(e) => props.setValue(e.currentTarget.value)}>
      <Show when={props.none}>
        <option value="">{props.none}</option>
      </Show>
      <optgroup label="The account's">
        <For each={props.policies.filter((p) => !p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
      </optgroup>
      <optgroup label="Cairn's (AWS's)">
        <For each={props.policies.filter((p) => p.aws)}>{(p) => <option value={p.arn}>{p.name}</option>}</For>
      </optgroup>
    </select>
  );
}

/** Several of a list to pick (policies to attach, groups to join), as
 * checkboxes. */
export function Checklist(props: { items: { id: string; label: string; note?: string }[]; chosen: string[]; setChosen: (c: string[]) => void; empty: string }) {
  const toggle = (id: string, on: boolean) => props.setChosen(on ? [...props.chosen, id] : props.chosen.filter((c) => c !== id));
  return (
    <div class="checklist">
      <For each={props.items} fallback={<span class="subtle small">{props.empty}</span>}>
        {(i) => (
          <label class="check">
            <input type="checkbox" checked={props.chosen.includes(i.id)} onChange={(e) => toggle(i.id, e.currentTarget.checked)} />
            <span class="mono">{i.label}</span>
            <Show when={i.note}>
              <span class="subtle small">{i.note}</span>
            </Show>
          </label>
        )}
      </For>
    </div>
  );
}

/** Attaching a managed policy to `target`: one it doesn't have yet. */
export function AttachDialog(props: {
  target: string;
  attached: string[];
  policies: ManagedPolicy[];
  attach: (arn: string) => Promise<unknown>;
  onClose: () => void;
  changed: () => void;
}) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const open = () => props.policies.filter((p) => !props.attached.includes(p.arn));
  const [arn, setArn] = createSignal(open().find((p) => !p.aws)?.arn ?? open()[0]?.arn ?? "");
  const chosen = () => props.policies.find((p) => p.arn === arn());
  const attach = async (e: SubmitEvent) => {
    e.preventDefault();
    const p = chosen();
    if (!p) return;
    if (await act(() => props.attach(p.arn), `Attached ${p.name} to ${props.target}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={attach}>
        <h2>
          Attach a policy to <span class="mono">{props.target}</span>
        </h2>
        <Show when={open().length} fallback={<p class="subtle">Every policy is attached already.</p>}>
          <PolicySelect policies={open()} value={arn()} setValue={setArn} />
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
          To give access that no policy covers yet, make one on the <A href="/policies">Policies</A> page.
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

/** An inline policy of `owner` (a user's, group's or role's), to view, edit
 * or delete (`policy`), or a new one. The server checks it, and says what's
 * wrong. */
export function InlinePolicyDialog(props: {
  owner: string;
  policy?: string;
  buckets: string[];
  load: (policy: string) => Promise<{ document: string }>;
  save: (policy: string, document: string) => Promise<unknown>;
  remove: (policy: string) => Promise<unknown>;
  /** What deleting it does, beyond the obvious. */
  removing?: string;
  note?: JSX.Element;
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
      setDocument(pretty((await props.load(props.policy)).document));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setLoading(false);
  });
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    try {
      await props.save(n, document());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved policy ${n} of ${props.owner}`);
    props.changed();
    dialog.close();
  };
  const remove = async () => {
    if (!confirm(`Delete policy "${props.policy}" of ${props.owner}?${props.removing ? " " + props.removing : ""}`)) return;
    if (await act(() => props.remove(props.policy!), `Deleted policy ${props.policy}`)) {
      props.changed();
      dialog.close();
    }
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          {props.policy ? "Inline policy" : "New inline policy"} of <span class="mono">{props.owner}</span>
        </h2>
        <Show
          when={!props.policy}
          fallback={<p class="mono">{props.policy}</p>}
        >
          <input
            type="text"
            placeholder="policy-name"
            aria-label="Policy name"
            autocomplete="off"
            required
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
          <p class="subtle small">
            An inline policy is its owner's alone. For access others share, or that's simpler to read later, make a
            managed policy (Policies) and attach it.
          </p>
        </Show>
        {props.note}
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

/** Tags, as rows to edit. */
export function TagRows(props: { tags: Tag[]; setTags: (t: Tag[]) => void }) {
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

/** Tags with an empty key dropped, keys trimmed. */
export const cleanTags = (tags: Tag[]) => tags.filter((t) => t.key.trim()).map((t) => ({ key: t.key.trim(), value: t.value }));

/** Tags, to read. */
export function TagChips(props: { tags: Tag[]; title?: string }) {
  return (
    <For each={props.tags} fallback={<span class="subtle">none</span>}>
      {(t) => (
        <span class="chip" title={props.title}>
          {t.key}={t.value}
        </span>
      )}
    </For>
  );
}
