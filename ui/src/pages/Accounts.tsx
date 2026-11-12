// The accounts (tenants, and the operator account), for superadmins: what
// each holds, making one, and its root's enrollment link for the console (a
// new account's first, or to recover it). See `src/accounts.rs`.

import { For, Show, createSignal } from "solid-js";
import { api } from "../api";
import { Badge, Loading, Panel, Table, act, poll } from "../components/ui";
import { bytes, date, num } from "../format";
import { EnrollmentDialog } from "./Users";

export default function Accounts() {
  const data = poll(() => api.accounts(), 10000);
  const [name, setName] = createSignal("");
  const [link, setLink] = createSignal<{ user: string; url?: string | null; path: string }>();
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    const n = name().trim();
    if (await act(() => api.createAccount(n), `Created account ${n}`)) {
      setName("");
      data.refresh();
    }
  };
  const enroll = async (account: string) => {
    const res = await act(() => api.rootEnrollment(account));
    if (res) setLink({ user: `root @ ${account}`, ...res.value });
  };
  return (
    <>
      <div class="page-head">
        <h1>Accounts</h1>
        <form class="form-row" onSubmit={create}>
          <input type="text" placeholder="new-account" aria-label="Account name" value={name()} onInput={(e) => setName(e.currentTarget.value)} />
          <button class="primary" type="submit">
            Create account
          </button>
        </form>
      </div>
      <p class="subtle small">
        Each account owns its users and buckets; bucket names are shared by all. An account's root signs in to the
        console through an enrollment link, and may do anything in its account. The operator account's users are the
        superadmins: it owns no buckets.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(list) => (
          <Panel>
            <Table
              count={list().length}
              columns={[
                "Name",
                "ID",
                { label: "Users", num: true },
                { label: "Buckets", num: true },
                { label: "Size", num: true },
                "Root",
                "Created",
                "",
              ]}
            >
              <For each={list()}>
                {(a) => (
                  <tr>
                    <td>
                      {a.name}{" "}
                      <Show when={a.operator}>
                        <Badge tone="warn">operator</Badge>
                      </Show>
                    </td>
                    <td class="mono small">{a.id}</td>
                    <td class="num">{num(a.users)}</td>
                    <td class="num">{num(a.buckets)}</td>
                    <td class="num">{bytes(a.bytes)}</td>
                    <td>{a.root_enrolled ? <Badge tone="ok">enrolled</Badge> : <span class="subtle">not yet</span>}</td>
                    <td>{date(a.created_at)}</td>
                    <td class="actions">
                      <button class="small" title="A one-time link for the account's root to the console" onClick={() => enroll(a.name)}>
                        Root link
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </Table>
          </Panel>
        )}
      </Show>
      <Show when={link()}>{(l) => <EnrollmentDialog {...l()} onClose={() => setLink(undefined)} />}</Show>
    </>
  );
}
