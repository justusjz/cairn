// Switching roles, as AWS's console has it: the session takes a role, in
// its account or another of the organization's, as STS's AssumeRole would
// let who signed in (the role's trust policy, and their own policies for
// another account's role), for an hour at most. The roles switched to
// lately are kept in the browser, as AWS's console keeps them.

import { useSearchParams } from "@solidjs/router";
import { For, Show, createResource, createSignal } from "solid-js";
import { Loading, Panel, Table } from "../components/ui";
import { clock } from "../format";
import { api } from "../session";
import { explain } from "../webauthn";

/** A role switched to lately. */
type Recent = { account: string; role: string; label?: string };

const RECENT_KEY = "cairn.recentRoles";
const MAX_RECENT = 5;

function recentRoles(): Recent[] {
  try {
    const list = JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]");
    return Array.isArray(list) ? list.filter((r) => typeof r?.account === "string" && typeof r?.role === "string") : [];
  } catch {
    return [];
  }
}

function remember(recent: Recent) {
  const others = recentRoles().filter((r) => r.account !== recent.account || r.role !== recent.role);
  localStorage.setItem(RECENT_KEY, JSON.stringify([recent, ...others].slice(0, MAX_RECENT)));
}

export default function SwitchRole() {
  const [params] = useSearchParams<{ account?: string; role?: string }>();
  const [me] = createResource(() => api.me());
  const [account, setAccount] = createSignal(params.account ?? "");
  const [role, setRole] = createSignal(params.role ?? "OrganizationAccountAccessRole");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [recent, setRecent] = createSignal(recentRoles());

  const go = async (target: Recent) => {
    setBusy(true);
    setError(undefined);
    try {
      const switched = await api.switchRole(target.account, target.role);
      remember({ ...target, label: switched.identity.account });
      // Every page's data is the role's now: start over.
      location.assign("/");
    } catch (e) {
      setError(explain(e));
      setBusy(false);
    }
  };
  const forget = (r: Recent) => {
    localStorage.setItem(RECENT_KEY, JSON.stringify(recentRoles().filter((o) => o.account !== r.account || o.role !== r.role)));
    setRecent(recentRoles());
  };

  return (
    <>
      <div class="page-head">
        <h1>Switch role</h1>
      </div>
      <p class="subtle small">
        Act as a role, in this account or another of the organization's, for an hour at most, as STS's AssumeRole
        would let you: the role's trust policy must allow you <span class="mono">sts:AssumeRole</span>, and for another
        account's role, your own policies must too. A member account's{" "}
        <span class="mono">OrganizationAccountAccessRole</span> trusts the management account, whose administrators
        may assume it. You switch from who you signed in as, and can switch back at any time.
      </p>
      <Show when={me()} fallback={<Loading error={me.error} />}>
        {(m) => (
          <Show when={m().switched}>
            {(s) => (
              <p class="small">
                You're acting as <span class="mono">{m().identity.arn}</span> until {clock(s().expires_at)}, switched
                from <span class="mono">{s().from}</span>.
              </p>
            )}
          </Show>
        )}
      </Show>
      <Panel title="Role">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void go({ account: account().trim(), role: role().trim() });
          }}
        >
          <label class="field">
            Account ID
            <input
              class="mono"
              required
              inputmode="numeric"
              pattern="[0-9]{12}"
              placeholder="123456789012"
              value={account()}
              onInput={(e) => setAccount(e.currentTarget.value)}
            />
          </label>
          <label class="field">
            Role (its name, after its path if it has one: team/deployer)
            <input class="mono" required value={role()} onInput={(e) => setRole(e.currentTarget.value)} />
          </label>
          <button class="primary" type="submit" disabled={busy()}>
            Switch role
          </button>
          <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        </form>
      </Panel>
      <Show when={recent().length}>
        <Panel title="Recent roles">
          <Table count={recent().length} columns={["Role", "Account", ""]}>
            <For each={recent()}>
              {(r) => (
                <tr>
                  <td class="mono">{r.role}</td>
                  <td>
                    {r.label ?? ""} <span class="mono small subtle">{r.account}</span>
                  </td>
                  <td class="actions">
                    <button class="small primary" disabled={busy()} onClick={() => go(r)}>
                      Switch
                    </button>
                    <button class="small" onClick={() => forget(r)}>
                      Forget
                    </button>
                  </td>
                </tr>
              )}
            </For>
          </Table>
        </Panel>
      </Show>
    </>
  );
}
