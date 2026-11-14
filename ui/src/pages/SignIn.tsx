// The OpenID Connect providers people may sign in to the console at, for
// operators: any provider that follows the standard, by its issuer URL
// and a client registered with it (see `src/console/oidc.rs`).

import { For, Show, createSignal } from "solid-js";
import { type OidcProvider, api } from "../api";
import { Loading, Panel, Table, act, poll } from "../components/ui";
import { num } from "../format";

export default function SignIn() {
  const data = poll(() => api.oidcConfig(), 30000);
  const [name, setName] = createSignal("");
  const [label, setLabel] = createSignal("");
  const [issuer, setIssuer] = createSignal("");
  const [clientId, setClientId] = createSignal("");
  const [secret, setSecret] = createSignal("");
  const [scopes, setScopes] = createSignal("openid email profile");
  const [editing, setEditing] = createSignal(false);
  const edit = (p: OidcProvider) => {
    setName(p.name);
    setLabel(p.label);
    setIssuer(p.issuer);
    setClientId(p.client_id);
    setSecret("");
    setScopes(p.scopes);
    setEditing(true);
  };
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    const body = { label: label(), issuer: issuer().trim(), client_id: clientId().trim(), client_secret: secret() || null, scopes: scopes() };
    if (await act(() => api.setOidcProvider(name().trim(), body), `Saved ${label()}`)) {
      setEditing(false);
      setName("");
      setLabel("");
      setIssuer("");
      setClientId("");
      setSecret("");
      data.refresh();
    }
  };
  const remove = async (p: OidcProvider) => {
    if (!confirm(`Remove ${p.label}? The ${p.logins} logins it signs in then sign in only with their other ways in.`)) return;
    if (await act(() => api.deleteOidcProvider(p.name), `Removed ${p.label}`)) data.refresh();
  };
  return (
    <>
      <div class="page-head">
        <h1>Sign-in</h1>
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
                        <button class="small" onClick={() => edit(p)}>
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
      <Panel title={editing() ? `Edit ${name()}` : "Add a provider"}>
        <form class="stacked" onSubmit={save}>
          <label class="field">
            Name (lowercase, in URLs)
            <input type="text" required disabled={editing()} value={name()} onInput={(e) => setName(e.currentTarget.value)} placeholder="company" />
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
            Client secret {editing() ? "(empty: keep it)" : "(empty: a public client)"}
            <input type="password" autocomplete="off" value={secret()} onInput={(e) => setSecret(e.currentTarget.value)} />
          </label>
          <label class="field">
            Scopes
            <input type="text" value={scopes()} onInput={(e) => setScopes(e.currentTarget.value)} />
          </label>
          <div class="form-row">
            <button class="primary" type="submit">
              {editing() ? "Save" : "Add provider"}
            </button>
            <Show when={editing()}>
              <button type="button" onClick={() => setEditing(false)}>
                Cancel
              </button>
            </Show>
          </div>
          <p class="subtle small">Saving checks the issuer's discovery document and keys.</p>
        </form>
      </Panel>
    </>
  );
}
