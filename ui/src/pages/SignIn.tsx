// The OpenID Connect providers people may sign in to the console at, for
// operators: any provider that follows the standard, by its issuer URL
// and a client registered with it (see `src/console/oidc.rs`).

import { For, Show, createSignal, onMount } from "solid-js";
import { type OidcProvider, api } from "../api";
import { Loading, Panel, Table, act, poll, toast } from "../components/ui";
import { num } from "../format";

export default function SignIn() {
  const data = poll(() => api.oidcConfig(), 30000);
  /** The provider being edited, or `null` for a new one. */
  const [editing, setEditing] = createSignal<OidcProvider | null>();
  const remove = async (p: OidcProvider) => {
    if (!confirm(`Remove ${p.label}? The ${p.logins} logins it signs in then sign in only with their other ways in.`)) return;
    if (await act(() => api.deleteOidcProvider(p.name), `Removed ${p.label}`)) data.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Sign-in</h1>
        <button class="primary" onClick={() => setEditing(null)}>
          New provider
        </button>
      </div>
      <p class="subtle small">
        People sign in to the console with passkeys, and with any OpenID Connect provider you add here (Keycloak,
        Authentik, Dex, Entra ID, Google, Okta, ...): its issuer URL and a client registered with it (confidential,
        with a secret, or public). An identity at a provider signs in only a login it's linked to, from an enrollment
        link or the account page; no account is entered for a matching e-mail address.
      </p>
      <Show when={data.data()} fallback={<Loading error={data.error()} />}>
        {(d) => (
          <>
            <Panel title="Redirect URI">
              <Show
                when={d().redirect_uri}
                fallback={<p class="subtle">This node doesn't serve the console: its redirect URI is the console URL's /api/oidc/callback.</p>}
              >
                {(uri) => (
                  <p>
                    Register <span class="mono">{uri()}</span> with each provider as the client's redirect URI.
                  </p>
                )}
              </Show>
            </Panel>
            <Panel title="Providers">
              <Table count={d().providers.length} empty="None: people sign in with passkeys only." columns={["Name", "Issuer", "Client", { label: "Logins", num: true }, ""]}>
                <For each={d().providers}>
                  {(p) => (
                    <tr>
                      <td>
                        {p.label}
                        <div class="subtle small mono">{p.name}</div>
                      </td>
                      <td class="mono small">{p.issuer}</td>
                      <td class="mono small">
                        {p.client_id}
                        <div class="subtle">{p.has_secret ? "confidential" : "public"} · {p.scopes}</div>
                      </td>
                      <td class="num">{num(p.logins)}</td>
                      <td class="actions">
                        <button class="small" onClick={() => setEditing(p)}>
                          Edit
                        </button>
                        <button class="small danger" onClick={() => remove(p)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </Table>
            </Panel>
          </>
        )}
      </Show>
      <Show when={editing() !== undefined}>
        <ProviderDialog provider={editing() ?? undefined} onClose={() => setEditing(undefined)} changed={data.refresh} />
      </Show>
    </>
  );
}

/** A sign-in provider to add, or to change (`provider`). */
function ProviderDialog(props: { provider?: OidcProvider; onClose: () => void; changed: () => void }) {
  let dialog!: HTMLDialogElement;
  onMount(() => dialog.showModal());
  const p = props.provider;
  const [name, setName] = createSignal(p?.name ?? "");
  const [label, setLabel] = createSignal(p?.label ?? "");
  const [issuer, setIssuer] = createSignal(p?.issuer ?? "");
  const [clientId, setClientId] = createSignal(p?.client_id ?? "");
  const [secret, setSecret] = createSignal("");
  const [scopes, setScopes] = createSignal(p?.scopes ?? "openid email profile");
  const [error, setError] = createSignal<string>();
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { label: label(), issuer: issuer().trim(), client_id: clientId().trim(), client_secret: secret() || null, scopes: scopes() };
    try {
      await api.setOidcProvider(name().trim(), body);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    toast(`Saved ${label()}`);
    props.changed();
    dialog.close();
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <form onSubmit={save}>
        <h2>{p ? `Edit ${p.label}` : "New sign-in provider"}</h2>
        <label class="field">
          Name (lowercase, in URLs)
          <input type="text" required disabled={!!p} value={name()} onInput={(e) => setName(e.currentTarget.value)} placeholder="company" />
        </label>
        <label class="field">
          Button label
          <input type="text" required value={label()} onInput={(e) => setLabel(e.currentTarget.value)} placeholder="Company SSO" />
        </label>
        <label class="field">
          Issuer URL
          <input type="url" required value={issuer()} onInput={(e) => setIssuer(e.currentTarget.value)} placeholder="https://sso.example.com/realms/main" />
        </label>
        <label class="field">
          Client ID
          <input type="text" required value={clientId()} onInput={(e) => setClientId(e.currentTarget.value)} />
        </label>
        <label class="field">
          Client secret {p ? "(empty: keep it)" : "(empty: a public client)"}
          <input type="password" autocomplete="off" value={secret()} onInput={(e) => setSecret(e.currentTarget.value)} />
        </label>
        <label class="field">
          Scopes
          <input type="text" value={scopes()} onInput={(e) => setScopes(e.currentTarget.value)} />
        </label>
        <p class="subtle small">Saving checks the issuer's discovery document and keys.</p>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <div class="buttons">
          <button type="button" onClick={() => dialog.close()}>
            Cancel
          </button>
          <button class="primary" type="submit">
            {p ? "Save" : "Add provider"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
