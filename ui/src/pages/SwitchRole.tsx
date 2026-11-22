// Switching roles, as AWS's console has it: the session takes a role, in
// its account or another of the organization's, as STS's AssumeRole would
// let who signed in (the role's trust policy, and their own policies for
// another account's role), for an hour at most. The roles switched to
// lately are kept in the browser, as AWS's console keeps them.

import { useSearchParams } from "@solidjs/router";
import { For, Show, createEffect, createResource, createSignal, on } from "solid-js";
import { accountName } from "../components/AccountName";
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
  // None to pick if they can't be listed: then the role is typed in.
  const [choices] = createResource(() => api.switchableRoles().catch(() => []));
  const [account, setAccount] = createSignal(params.account ?? "");
  const [role, setRole] = createSignal(params.role ?? "OrganizationAccountAccessRole");
  // Typed in rather than picked: when the link named a role that isn't one
  // to pick, or by choice.
  const [manual, setManual] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [recent, setRecent] = createSignal(recentRoles());

  /** The accounts with a role to pick, in order, with their names. */
  const accounts = () => {
    const seen = new Map<string, string>();
    for (const c of choices() ?? []) if (!seen.has(c.account_id)) seen.set(c.account_id, c.account);
    return [...seen].map(([id, name]) => ({ id, name }));
  };
  const rolesOf = (id: string) => (choices() ?? []).filter((c) => c.account_id === id);
  const chosen = () => rolesOf(account()).find((c) => c.role === role());
  const nameOf = (id: string) => (choices() ?? []).find((c) => c.account_id === id)?.account ?? accountName(id);

  // Once the roles are in, pick what the link named if it's one of them
  // (else type it in), or the first account's first role.
  createEffect(
    on(choices, (list) => {
      if (!list) return;
      if (params.account) {
        const found = list.find((c) => c.account_id === params.account && c.role.toLowerCase() === role().toLowerCase());
        if (found) setRole(found.role);
        else setManual(true);
      } else if (list.length) {
        pickAccount(list[0].account_id);
      } else {
        setManual(true);
      }
    }),
  );
  const pickAccount = (id: string) => {
    setAccount(id);
    const roles = rolesOf(id);
    if (!roles.some((r) => r.role === role())) {
      setRole(roles.find((r) => r.role === "OrganizationAccountAccessRole")?.role ?? roles[0]?.role ?? "");
    }
  };

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
        <Show when={choices()} fallback={<Loading />}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void go({ account: account().trim(), role: role().trim() });
            }}
          >
            <Show
              when={!manual()}
              fallback={
                <>
                  <Show when={choices()?.length === 0}>
                    <p class="subtle small">
                      There's no role to pick: none trusts you now. Name one yourself, if you know of one.
                    </p>
                  </Show>
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
                    <Show when={nameOf(account().trim())}>{(n) => <span class="subtle small">{n()}</span>}</Show>
                  </label>
                  <label class="field">
                    Role (its name, after its path if it has one: team/deployer)
                    <input class="mono" required value={role()} onInput={(e) => setRole(e.currentTarget.value)} />
                  </label>
                </>
              }
            >
              <label class="field">
                Account
                <select value={account()} onChange={(e) => pickAccount(e.currentTarget.value)}>
                  <For each={accounts()}>{(a) => <option value={a.id}>{`${a.name} (${a.id})`}</option>}</For>
                </select>
              </label>
              <label class="field">
                Role
                <select class="mono" value={role()} onChange={(e) => setRole(e.currentTarget.value)}>
                  <For each={rolesOf(account())}>{(r) => <option value={r.role}>{r.role}</option>}</For>
                </select>
                <Show when={chosen()?.description}>{(d) => <span class="subtle small">{d()}</span>}</Show>
              </label>
            </Show>
            <div class="buttons">
              <button class="primary" type="submit" disabled={busy() || !account() || !role()}>
                Switch role
              </button>
              <Show when={choices()?.length}>
                <button
                  type="button"
                  class="small"
                  onClick={() => {
                    if (manual()) pickAccount(accounts().some((a) => a.id === account()) ? account() : accounts()[0].id);
                    setManual(!manual());
                  }}
                >
                  {manual() ? "Pick from the roles that trust you" : "Enter an account and role by hand"}
                </button>
              </Show>
            </div>
            <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
            <p class="subtle small">
              The roles to pick are those whose trust policies allow you now (and, in another account, your own
              policies too).
            </p>
          </form>
        </Show>
      </Panel>
      <Show when={recent().length}>
        <Panel title="Recent roles">
          <Table count={recent().length} columns={["Role", "Account", ""]}>
            <For each={recent()}>
              {(r) => (
                <tr>
                  <td class="mono">{r.role}</td>
                  <td>
                    {nameOf(r.account) ?? r.label ?? ""} <span class="mono small subtle">{r.account}</span>
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
