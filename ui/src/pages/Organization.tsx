// The organization (as AWS Organizations'): the management account, which
// owns the cluster, and its member accounts, made here and closed here.

import { For, Show, createSignal, onMount } from "solid-js";
import { type OrgAccount, api } from "../api";
import { Badge, Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { date } from "../format";

export default function Organization() {
  const data = poll(() => api.accounts(), 10000);
  const [creating, setCreating] = createSignal(false);
  const close = async (a: OrgAccount) => {
    if (!confirm(`Close ${a.name} (${a.id})? At once: its users, roles and sessions stop working, and it can't be reopened.`)) return;
    if (await act(() => api.closeAccount(a.id), `Closed ${a.name}`)) data.refresh();
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
        {(accounts) => (
          <Panel title="Accounts" note={`${accounts().length}`}>
            <Table count={accounts().length} empty="None." columns={["Name", "ID", "E-mail", "Joined", "Buckets", ""]}>
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
                    <td>{date(a.joined_at)}</td>
                    <td class="num">{a.buckets}</td>
                    <td class="actions">
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
        )}
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
          principals may assume (if their own policies allow <span class="mono">sts:AssumeRole</span>).
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
