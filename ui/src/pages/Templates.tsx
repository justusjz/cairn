// Policy templates (see `src/templates.rs`): managed policies for common
// setups, made as IAM's CreatePolicy by the signed-in identity (so a team's
// admin may use them within its team). Above all the team: an account
// shared by teams, each with a policy for everything it may do (its admins'
// policy, and everyone's boundary) and a member policy, made where the team
// can't change them.

import { For, Show, createResource, createSignal, onMount } from "solid-js";
import { type Level, type MadePolicy, type TemplateUse, api } from "../api";
import { act } from "../components/ui";
import { pretty } from "../format";

const LEVELS: { id: Level; label: string }[] = [
  { id: "read", label: "Read" },
  { id: "write", label: "Write" },
  { id: "delete-version", label: "Delete versions" },
  { id: "manage", label: "Manage" },
];

/** Picks a template, fills it in, shows what it makes, and makes it. */
export function TemplateDialog(props: { onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  const [templates] = createResource(() => api.templates());
  const [id, setId] = createSignal("team");
  // The team's.
  const [team, setTeam] = createSignal("");
  const [prefix, setPrefix] = createSignal("");
  const [listBuckets, setListBuckets] = createSignal(false);
  const [listPolicies, setListPolicies] = createSignal(false);
  // Bucket access's and the MFA guard's.
  const [buckets, setBuckets] = createSignal("");
  const [levels, setLevels] = createSignal<Level[]>(["read"]);
  const [name, setName] = createSignal("");
  const [path, setPath] = createSignal("");
  const [preview, setPreview] = createSignal<MadePolicy[]>();
  const [error, setError] = createSignal<string>();
  const [made, setMade] = createSignal<MadePolicy[]>();
  onMount(() => dialog.showModal());

  const use = (): TemplateUse => {
    const optional = (s: string) => s.trim() || null;
    switch (id()) {
      case "team":
        return {
          template: "team",
          team: team().trim(),
          bucket_prefix: optional(prefix()),
          list_all_buckets: listBuckets(),
          list_policies: listPolicies(),
        };
      case "bucket-access":
        return { template: "bucket-access", buckets: buckets().trim(), levels: levels(), name: optional(name()), path: optional(path()) };
      default:
        return { template: "mfa-guard", name: optional(name()), path: optional(path()) };
    }
  };
  // What's shown is what's made: any change takes the preview back.
  const changed = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setPreview(undefined);
    setError(undefined);
  };
  const show = async () => {
    try {
      setPreview(await api.previewTemplate(use()));
      setError(undefined);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  const make = async () => {
    const res = await act(() => api.useTemplate(use()), "Made the template's policies");
    if (res) {
      setMade(res.value);
      props.changed();
    }
  };
  const toggle = (l: Level, on: boolean) =>
    changed(setLevels)(on ? [...levels(), l].filter((x, i, all) => all.indexOf(x) === i) : levels().filter((x) => x !== l));
  const template = () => templates()?.find((t) => t.id === id());

  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <h2>From a template</h2>
      <Show
        when={!made()}
        fallback={
          <>
            <p>Made:</p>
            <For each={made()}>{(p) => <p class="mono small">{p.arn}</p>}</For>
            <Show when={id() === "team"}>
              <p class="subtle small">
                Give a team's admin (a user or a role at <span class="mono">/{team().trim()}/</span>) the{" "}
                <span class="mono">{team().trim()}-team</span> policy, both attached and as its permissions boundary.
                Its admins then make the team's users and roles (with that boundary: they can't make any without it)
                and give them <span class="mono">{team().trim()}-member</span>, or what else they need.
              </p>
            </Show>
            <div class="buttons">
              <button type="button" class="primary" onClick={() => dialog.close()}>
                Done
              </button>
            </div>
          </>
        }
      >
        <div class="form-row">
          <select aria-label="Template" value={id()} onChange={(e) => changed(setId)(e.currentTarget.value)}>
            <For each={templates() ?? []}>{(t) => <option value={t.id}>{t.title}</option>}</For>
          </select>
        </div>
        <Show when={template()}>{(t) => <p class="subtle small">{t().description}</p>}</Show>

        <Show when={id() === "team"}>
          <input
            type="text"
            placeholder="team name"
            aria-label="Team name"
            autocomplete="off"
            value={team()}
            onInput={(e) => changed(setTeam)(e.currentTarget.value)}
          />
          <input
            type="text"
            placeholder={`bucket prefix (default: ${team().trim().toLowerCase() || "team"}-)`}
            aria-label="Bucket prefix"
            title="The team's buckets are those whose names start with this"
            autocomplete="off"
            value={prefix()}
            onInput={(e) => changed(setPrefix)(e.currentTarget.value)}
          />
          <label class="small">
            <input type="checkbox" checked={listBuckets()} onChange={(e) => changed(setListBuckets)(e.currentTarget.checked)} />{" "}
            The team sees every bucket's name (ListBuckets: S3 can't list only some)
          </label>
          <label class="small">
            <input type="checkbox" checked={listPolicies()} onChange={(e) => changed(setListPolicies)(e.currentTarget.checked)} />{" "}
            Its admins see every policy's name (ListPolicies: IAM can't list only some; the console lists them the
            policies they may read anyway)
          </label>
        </Show>

        <Show when={id() === "bucket-access"}>
          <input
            type="text"
            placeholder="bucket, or a pattern (team-*)"
            aria-label="Buckets"
            autocomplete="off"
            value={buckets()}
            onInput={(e) => changed(setBuckets)(e.currentTarget.value)}
          />
          <div class="form-row">
            <For each={LEVELS}>
              {(l) => (
                <label class="small">
                  <input type="checkbox" checked={levels().includes(l.id)} onChange={(e) => toggle(l.id, e.currentTarget.checked)} />{" "}
                  {l.label}
                </label>
              )}
            </For>
          </div>
        </Show>

        <Show when={id() !== "team"}>
          <input
            type="text"
            placeholder="policy name (optional)"
            aria-label="Policy name"
            autocomplete="off"
            value={name()}
            onInput={(e) => changed(setName)(e.currentTarget.value)}
          />
          <input
            type="text"
            placeholder="/path/ (optional; a team's admin: its team's)"
            aria-label="Path"
            autocomplete="off"
            value={path()}
            onInput={(e) => changed(setPath)(e.currentTarget.value)}
          />
        </Show>

        <Show when={error()}>{(e) => <p class="error-text small">{e()}</p>}</Show>
        <Show when={preview()}>
          {(policies) => (
            <For each={policies()}>
              {(p) => (
                <>
                  <p class="mono small">{p.arn}</p>
                  <p class="subtle small">{p.description}</p>
                  <div class="pem">{pretty(p.document)}</div>
                </>
              )}
            </For>
          )}
        </Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <Show when={preview()} fallback={<button type="button" class="primary" onClick={show}>Preview</button>}>
            <button type="button" class="primary" onClick={make}>
              Make {preview()!.length === 1 ? "it" : `these ${preview()!.length}`}
            </button>
          </Show>
        </div>
      </Show>
    </dialog>
  );
}
