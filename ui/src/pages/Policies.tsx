// An account's managed policies (see `src/managed.rs`): Cairn's, which have
// AWS's names and say what AWS's do, and the account's own, which are
// attached to users on the Users page. Making, changing (a new version) and
// deleting (once nothing has it attached) the account's own.

import { For, Show, createSignal, onMount } from "solid-js";
import { type ManagedPolicy, api } from "../api";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { EMPTY, PolicyEditor } from "../components/PolicyEditor";
import { ago, pretty } from "../format";

export default function Policies() {
  const data = poll(() => Promise.all([api.policies(), api.buckets()]), 10000);
  const [open, setOpen] = createSignal<{ policy?: ManagedPolicy }>();
  const remove = async (p: ManagedPolicy) => {
    if (!confirm(`Delete policy "${p.name}"?`)) return;
    if (await act(() => api.deleteManagedPolicy(p.name), `Deleted ${p.name}`)) data.refresh();
  };
  const buckets = () => (data.data()?.[1] ?? []).map((b) => b.name);
  return (
    <>
      <div class="page-head">
        <h1>Policies</h1>
        <button class="primary" onClick={() => setOpen({})}>
          New policy
        </button>
      </div>
      <p class="subtle small">
        Managed policies are documents of their own, attached to any number of users (on the Users page): what a user
        may do is what its attached and inline policies allow, and its buckets' policies, where they name it; a Deny
        wins over any Allow. Cairn's own have AWS's names and say what AWS's do, so policies and tools written for AWS
        work as they are.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <Panel>
            <Table count={d()[0].length} columns={["Name", "Description", "Attached to", "Version", ""]}>
              <For each={d()[0]}>
                {(p) => (
                  <tr>
                    <td>
                      <span class="mono">{p.name}</span>{" "}
                      <Show when={p.aws}>
                        <Badge>Cairn's (AWS)</Badge>
                      </Show>
                    </td>
                    <td class="small">{p.description || <span class="subtle">–</span>}</td>
                    <td>
                      <Show when={p.users.length} fallback={<span class="subtle">no one</span>}>
                        <For each={p.users}>{(u) => <span class="chip mono">{u}</span>}</For>
                      </Show>
                    </td>
                    <td class="small">
                      v{p.version}
                      <Show when={p.updated_at}>{(t) => <div class="subtle">{ago(t())}</div>}</Show>
                    </td>
                    <td class="actions">
                      <button class="small" onClick={() => setOpen({ policy: p })}>
                        {p.aws ? "View" : "Edit"}
                      </button>
                      <Show when={!p.aws}>
                        <button
                          class="small danger"
                          disabled={p.users.length > 0}
                          title={p.users.length ? "Detach it from its users first" : ""}
                          onClick={() => remove(p)}
                        >
                          Delete
                        </button>
                      </Show>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={open()}>
        {(o) => (
          <ManagedPolicyDialog
            policy={o().policy}
            buckets={buckets()}
            onClose={() => setOpen(undefined)}
            changed={data.refresh}
          />
        )}
      </Show>
    </>
  );
}

/** A managed policy to view (Cairn's), edit, or make (`policy` not given). */
function ManagedPolicyDialog(props: {
  policy?: ManagedPolicy;
  buckets: string[];
  onClose: () => void;
  changed: () => void;
}) {
  let dialog!: HTMLDialogElement;
  const p = props.policy;
  const [name, setName] = createSignal(p?.name ?? "");
  const [description, setDescription] = createSignal(p?.description ?? "");
  const [document, setDocument] = createSignal(p ? pretty(p.document) : EMPTY);
  const [error, setError] = createSignal<string>();
  onMount(() => dialog.showModal());
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      if (p) {
        const change: { document?: string; description?: string } = {};
        if (document() !== pretty(p.document)) change.document = document();
        if (description() !== p.description) change.description = description();
        await api.updatePolicy(p.name, change);
      } else {
        await api.createPolicy(name().trim(), document(), description());
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved ${p?.name ?? name().trim()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} class="wide" onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>
          <Show when={p} fallback="New policy">
            {(p) => (
              <>
                <span class="mono">{p().name}</span> <span class="subtle small">v{p().version}</span>
              </>
            )}
          </Show>
        </h2>
        <Show when={p}>{(p) => <p class="mono small subtle">{p().arn}</p>}</Show>
        <Show when={!p}>
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
        <input
          type="text"
          placeholder="What it's for (optional)"
          aria-label="Description"
          readOnly={p?.aws}
          value={description()}
          onInput={(e) => setDescription(e.currentTarget.value)}
        />
        <PolicyEditor document={document()} setDocument={setDocument} buckets={props.buckets} readOnly={p?.aws} />
        <Show when={p?.aws}>
          <p class="subtle small">Cairn's policies are AWS's, and can't be changed: make one of your own instead.</p>
        </Show>
        <Show when={p && !p.aws && p.users.length}>
          <p class="subtle small">
            Saving makes a new version, which applies to everyone it's attached to at once: {p!.users.join(", ")}.
          </p>
        </Show>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            {p?.aws ? "Close" : "Cancel"}
          </button>
          <Show when={!p?.aws}>
            <button class="primary" type="submit">
              {p ? "Save" : "Create"}
            </button>
          </Show>
        </div>
      </form>
    </dialog>
  );
}
