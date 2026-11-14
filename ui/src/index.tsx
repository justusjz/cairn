// The console (see `src/console/`): signing in, with a passkey or at an
// OIDC provider, a first passkey through an enrollment link, one's own
// passkeys, and the pages of what the signed-in identity manages: the
// account's buckets, objects, users and policies, and, for its operators
// (whose policies allow `cairn:` actions), the cluster.

import { A, Navigate, Route, Router, type RouteSectionProps, useNavigate } from "@solidjs/router";
import { For, Show, createEffect, createResource, createRoot, createSignal, onCleanup } from "solid-js";
import { render } from "solid-js/web";
import { Badge, Loading, Panel, Table, Toasts, act, poll, toast } from "./components/ui";
import { ago, date } from "./format";
import { api as manage, setOperatorMode } from "./api";
import { BucketBrowser, BucketList, ObjectPage } from "./pages/Buckets";
import Integrity from "./pages/Integrity";
import Jobs from "./pages/Jobs";
import Lifecycle from "./pages/Lifecycle";
import Overview from "./pages/Overview";
import Policies from "./pages/Policies";
import Storage from "./pages/Storage";
import SignIn from "./pages/SignIn";
import Users from "./pages/Users";
import "./styles.css";
import { ApiError, type Identity, type Me, type Passkey, api } from "./session";
import { authenticate, deviceName, explain, register, supported } from "./webauthn";

/** Who's signed in: `null` if no one, undefined while asking. */
const [me, { refetch: refreshMe, mutate: setMe }] = createResource<Me | null>(async () => {
  try {
    return await api.me();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
});

// The shared pages show the cluster's parts (the KMS) to its operators.
createRoot(() => createEffect(() => setOperatorMode(me()?.cluster ?? false)));

function Brand() {
  return (
    <A class="brand" href="/">
      <svg viewBox="0 0 32 32" aria-hidden="true">
        <ellipse cx="16" cy="27" rx="12" ry="4" />
        <ellipse cx="16" cy="19" rx="9" ry="3.6" />
        <ellipse cx="16" cy="12" rx="6.5" ry="3" />
        <ellipse cx="16" cy="6" rx="4" ry="2.4" />
      </svg>
      Cairn
    </A>
  );
}

/** A count next to the Integrity link, on every page: objects with lost data
 * (bad), else open findings (being looked into, or a node down). */
function IntegrityCount() {
  const integrity = poll(manage.integrity, 30000);
  const lost = () => integrity.data()?.lost_objects ?? 0;
  const open = () => integrity.data()?.open_findings ?? 0;
  return (
    <Show when={lost() || open()}>
      <span
        class={"nav-count " + (lost() ? "bad" : "warn")}
        title={lost() ? `${lost()} objects with lost data` : `${open()} open findings`}
      >
        {lost() || open()}
      </span>
    </Show>
  );
}

function Layout(props: RouteSectionProps) {
  const navigate = useNavigate();
  const logout = async () => {
    if (await act(() => api.logout())) {
      setMe(null);
      navigate("/login");
    }
  };
  return (
    <>
      <header class="topbar">
        <Brand />
        <nav>
          <Show when={me()}>
            {(m) => (
              <For each={m().cluster ? [...CLUSTER_NAV, ...ACCOUNT_NAV, ...OPERATOR_NAV] : ACCOUNT_NAV}>
                {([href, label]) => (
                  <A href={href} end={href === "/"} activeClass="active">
                    {label}
                    {href === "/integrity" && <IntegrityCount />}
                  </A>
                )}
              </For>
            )}
          </Show>
        </nav>
        <Show when={me()}>{(m) => <UserMenu me={m()} logout={logout} />}</Show>
      </header>
      <main>{props.children}</main>
      <Toasts />
    </>
  );
}

/** What everyone sees: the account's buckets, users and policies (each page
 * shows what the identity's policies let it see). */
const ACCOUNT_NAV: [string, string][] = [
  ["/buckets", "Buckets"],
  ["/users", "Users"],
  ["/policies", "Policies"],
];

/** What the cluster's operators see first: the cluster. */
const CLUSTER_NAV: [string, string][] = [
  ["/", "Overview"],
  ["/storage", "Storage"],
  ["/integrity", "Integrity"],
  ["/jobs", "Jobs"],
];

/** ... and last: how people sign in. */
const OPERATOR_NAV: [string, string][] = [["/sign-in", "Sign-in"]];

/** The user's name. */
function label(i: Identity): string {
  return i.user;
}

/** The person signed in: who the session acts as, their own sign-in
 * settings, and signing out. */
function UserMenu(props: { me: Me; logout: () => void }) {
  const [open, setOpen] = createSignal(false);
  let menu!: HTMLDivElement;
  const close = (e: MouseEvent) => {
    if (!menu.contains(e.target as Node)) setOpen(false);
  };
  const key = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
  createEffect(() => {
    if (open()) {
      document.addEventListener("click", close);
      document.addEventListener("keydown", key);
    } else {
      document.removeEventListener("click", close);
      document.removeEventListener("keydown", key);
    }
  });
  onCleanup(() => {
    document.removeEventListener("click", close);
    document.removeEventListener("keydown", key);
  });
  return (
    <div class="user-menu" ref={menu}>
      <button class="user-button" aria-haspopup="menu" aria-expanded={open()} onClick={() => setOpen(!open())}>
        <span class="avatar" aria-hidden="true">
          {props.me.name.slice(0, 1).toUpperCase()}
        </span>
        <span class="mono">{label(props.me.identity)}</span>
        <Show when={props.me.cluster}>
          <Badge tone="warn">operator</Badge>
        </Show>
        <span aria-hidden="true">▾</span>
      </button>
      <Show when={open()}>
        <div class="menu" role="menu">
          <div class="menu-head">
            Signed in as <strong>{props.me.name}</strong>
          </div>
          <hr />
          <A role="menuitem" class="menu-item" href="/account" onClick={() => setOpen(false)}>
            Passkeys and sign-in
          </A>
          <button role="menuitem" class="menu-item" onClick={props.logout}>
            Sign out
          </button>
        </div>
      </Show>
    </div>
  );
}

/** A page for the signed-in only. */
function SignedIn(props: { children: (me: Me) => import("solid-js").JSX.Element }) {
  return (
    <Show when={me.state !== "pending" && me.state !== "refreshing"} fallback={<Loading />}>
      <Show when={!me.error} fallback={<Loading error={(me.error as Error).message} />}>
        <Show when={me()} fallback={<Navigate href="/login" />}>
          {(m) => props.children(m())}
        </Show>
      </Show>
    </Show>
  );
}

/** The OIDC providers to continue with, for `purpose`. */
function ProviderButtons(props: { purpose: "login" | "enroll"; token?: string; onError: (e: string) => void }) {
  const [providers] = createResource(() => api.oidcProviders().catch(() => []));
  const go = async (name: string) => {
    try {
      const { url } = await api.oidcStart(name, props.purpose, { token: props.token });
      location.assign(url);
    } catch (e) {
      props.onError(explain(e));
    }
  };
  return (
    <Show when={providers()?.length}>
      <div class="provider-buttons">
        <For each={providers()}>
          {(p) => (
            <button type="button" onClick={() => go(p.name)}>
              Continue with {p.label}
            </button>
          )}
        </For>
      </div>
    </Show>
  );
}

/** What a provider's sign-in sent back as wrong (`?error=`), once. */
function takeError(): string | undefined {
  const error = new URLSearchParams(location.search).get("error") ?? undefined;
  if (error) history.replaceState(null, "", location.pathname + location.hash);
  return error;
}

function NoPasskeys() {
  return (
    <p class="error-text">
      This browser can't use passkeys. Use a current browser, on a device with a screen lock, or a security key.
    </p>
  );
}

function Login() {
  const navigate = useNavigate();
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | undefined>(takeError());
  const signIn = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const ceremony = await api.loginOptions();
      const credential = await authenticate(ceremony.options);
      setMe(await api.login(ceremony.challenge_id, credential));
      navigate("/");
    } catch (e) {
      setError(explain(e));
    }
    setBusy(false);
  };
  return (
    <div class="signin">
      <Panel title="Sign in to Cairn">
        <Show when={supported()} fallback={<NoPasskeys />}>
          <p class="subtle">Sign in with a passkey: your device asks for your fingerprint, face, PIN or security key.</p>
          <button class="primary" disabled={busy()} onClick={signIn}>
            Sign in with a passkey
          </button>
          <ProviderButtons purpose="login" onError={setError} />
          <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
          <p class="subtle small">
            New here? Ask an administrator for an enrollment link.
          </p>
        </Show>
      </Panel>
    </div>
  );
}

function Enroll() {
  const navigate = useNavigate();
  const token = location.hash.slice(1);
  // The token stays out of the history and the address bar once read.
  history.replaceState(null, "", location.pathname);
  const [ceremony] = createResource(async () => (token ? api.enrollOptions(token) : Promise.reject(new Error("This link has no token."))));
  /** Signed in: the link's identity joins this login, with no new passkey. */
  const link = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setMe(await api.enrollLink(token));
      toast(`Added ${ceremony()?.identity ?? "the account"} to your login`);
      navigate("/account");
    } catch (e) {
      setError(explain(e));
      setBusy(false);
    }
  };
  const [name, setName] = createSignal(deviceName());
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const enroll = async (e: SubmitEvent) => {
    e.preventDefault();
    const c = ceremony();
    if (!c) return;
    setBusy(true);
    setError(undefined);
    try {
      const credential = await register(c.options);
      setMe(await api.enroll(token, c.challenge_id, name(), credential));
      toast("Your passkey is set up");
      navigate("/account");
    } catch (e) {
      setError(explain(e));
      setBusy(false);
    }
  };
  return (
    <div class="signin">
      <Panel title="Set up your sign-in">
        <Show when={supported()} fallback={<NoPasskeys />}>
          <Show when={ceremony()} fallback={<Loading error={ceremony.error && (ceremony.error as Error).message} />}>
            {(c) => (
              <form onSubmit={enroll}>
                <Show when={me()}>
                  {(m) => (
                    <>
                      <p>
                        You're signed in as <span class="mono">{m().name}</span>. Add{" "}
                        <span class="mono">{c().identity}</span> to this login, to switch to it with the same passkeys:
                      </p>
                      <button type="button" class="primary" disabled={busy()} onClick={link}>
                        Add to my login
                      </button>
                      <p class="subtle small">Or make a separate login for it, with a passkey of its own:</p>
                    </>
                  )}
                </Show>
                <p>
                  Welcome, <span class="mono">{c().identity}</span>. Make a passkey for this console: your device keeps
                  it, and asks for your fingerprint, face, PIN or security key when you sign in. There's no password.
                </p>
                <label class="field">
                  Name it
                  <input type="text" required maxLength={64} value={name()} onInput={(e) => setName(e.currentTarget.value)} />
                </label>
                <button class="primary" type="submit" disabled={busy()}>
                  Make a passkey
                </button>
                <ProviderButtons purpose="enroll" token={token} onError={setError} />
                <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
                <p class="subtle small">This link works once. If it doesn't anymore, ask for a new one.</p>
              </form>
            )}
          </Show>
        </Show>
      </Panel>
    </div>
  );
}

/** A page for the signed-in only. */
function Guarded(page: () => import("solid-js").JSX.Element) {
  return () => <SignedIn>{() => page()}</SignedIn>;
}

/** The start: the cluster's overview to its operators, the buckets to
 * anyone else. */
function Start() {
  return (
    <Show when={me()?.cluster} fallback={<Navigate href="/buckets" />}>
      <Overview />
    </Show>
  );
}

function Home() {
  return (
    <SignedIn>
      {(m) => (
        <>
          <div class="page-head">
            <h1>Your sign-in</h1>
            <span class="subtle small">login {m.name}</span>
          </div>
          <Passkeys passkeys={m.passkeys} others={m.oidc.length} />
          <Providers me={m} />
          <Panel title="Who you are">
            <Table count={1} columns={["As", "ARN"]}>
              <tr>
                <td>
                  {m.identity.user}{" "}
                  <Show when={m.identity.admin}>
                    <Badge tone="accent">admin</Badge>
                  </Show>{" "}
                  <Show when={m.cluster}>
                    <Badge tone="warn">operator</Badge>
                  </Show>
                </td>
                <td class="mono small">{m.identity.arn}</td>
              </tr>
            </Table>
            <p class="subtle small">
              Policies name you by the ARN: what you may do here is what your policies allow, and what buckets'
              policies don't deny you. You're an operator if your policies allow
              you the cluster's actions (<span class="mono">cairn:*</span>). Signed in with a passkey, your session
              counts as multi-factor (<span class="mono">aws:MultiFactorAuthPresent</span>); at a provider, it
              doesn't.
            </p>
          </Panel>
        </>
      )}
    </SignedIn>
  );
}

/** The login's identities at OIDC providers, which sign it in too: linking
 * one (at the provider), and unlinking (not the last way in). */
function Providers(props: { me: Me }) {
  const [providers] = createResource(() => api.oidcProviders().catch(() => []));
  const [error, setError] = createSignal<string | undefined>(takeError());
  const unlinked = () => (providers() ?? []).filter((p) => !props.me.oidc.some((o) => o.provider === p.name));
  const link = async (name: string) => {
    try {
      const { url } = await api.oidcStart(name, "link");
      location.assign(url);
    } catch (e) {
      setError(explain(e));
    }
  };
  const unlink = async (provider: string, label: string) => {
    if (!confirm(`Stop signing in with ${label}?`)) return;
    if (await act(() => api.oidcUnlink(provider), `Unlinked ${label}`)) refreshMe();
  };
  return (
    <Show when={providers()?.length || props.me.oidc.length}>
      <Panel title="Sign-in providers">
        <Table count={props.me.oidc.length} empty="None linked." columns={["Provider", "As", ""]}>
          <For each={props.me.oidc}>
            {(o) => (
              <tr>
                <td>
                  {o.label}{" "}
                  <Show when={props.me.signed_in_at === o.provider}>
                    <Badge tone="ok">this session</Badge>
                  </Show>
                </td>
                <td>{o.email ?? <span class="subtle">no e-mail given</span>}</td>
                <td class="actions">
                  <button
                    class="small danger"
                    disabled={props.me.passkeys.length + props.me.oidc.length <= 1}
                    title={props.me.passkeys.length + props.me.oidc.length <= 1 ? "Your last way to sign in" : ""}
                    onClick={() => unlink(o.provider, o.label)}
                  >
                    Unlink
                  </button>
                </td>
              </tr>
            )}
          </For>
        </Table>
        <For each={unlinked()}>
          {(p) => (
            <button class="small" onClick={() => link(p.name)}>
              Link {p.label}
            </button>
          )}
        </For>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
      </Panel>
    </Show>
  );
}

function Passkeys(props: { passkeys: Passkey[]; others: number }) {
  const add = async () => {
    try {
      const ceremony = await api.passkeyOptions();
      const credential = await register(ceremony.options);
      const name = prompt("Name the new passkey", deviceName());
      if (name === null) return;
      await api.addPasskey(ceremony.challenge_id, name, credential);
      toast("Passkey added");
      refreshMe();
    } catch (e) {
      toast(explain(e), true);
    }
  };
  const rename = async (p: Passkey) => {
    const name = prompt("Rename the passkey", p.name);
    if (name === null || name === p.name) return;
    if (await act(() => api.renamePasskey(p.id, name), "Renamed")) refreshMe();
  };
  const remove = async (p: Passkey) => {
    const also = p.current ? " You're signed in with it, so you'll be signed out." : "";
    if (!confirm(`Remove the passkey "${p.name}"?${also}`)) return;
    if (!(await act(() => api.deletePasskey(p.id), "Passkey removed"))) return;
    refreshMe();
  };
  return (
    <Panel title="Passkeys" note={`${props.passkeys.length} of 8`}>
      <Table count={props.passkeys.length} columns={["Name", "Synced", "Added", "Last used", ""]}>
        <For each={props.passkeys}>
          {(p) => (
            <tr>
              <td>
                {p.name}{" "}
                <Show when={p.current}>
                  <Badge tone="ok">this session</Badge>
                </Show>
              </td>
              <td>{p.backed_up ? "yes" : <span class="subtle">no</span>}</td>
              <td>{date(p.created_at)}</td>
              <td>{p.last_used_at ? ago(p.last_used_at) : <span class="subtle">never</span>}</td>
              <td class="actions">
                <button class="small" onClick={() => rename(p)}>
                  Rename
                </button>
                <button
                  class="small danger"
                  disabled={props.passkeys.length + props.others <= 1}
                  title={props.passkeys.length + props.others <= 1 ? "Your last way to sign in" : ""}
                  onClick={() => remove(p)}
                >
                  Remove
                </button>
              </td>
            </tr>
          )}
        </For>
      </Table>
      <button class="small" disabled={props.passkeys.length >= 8} onClick={add}>
        Add a passkey
      </button>
      <p class="subtle small">
        A second passkey (another device, or a security key) keeps you from being locked out if you lose one. Synced
        passkeys are backed up by their provider (iCloud Keychain, Google Password Manager, a password manager).
      </p>
    </Panel>
  );
}

function NotFound() {
  return (
    <>
      <h1>Not found</h1>
      <p>
        There's no page here. <A href="/">Back</A>
      </p>
    </>
  );
}

render(
  () => (
    <Router root={Layout} explicitLinks>
      <Route path="/" component={Guarded(Start)} />
      <Route path="/storage" component={Guarded(Storage)} />
      <Route path="/integrity" component={Guarded(Integrity)} />
      <Route path="/jobs" component={Guarded(Jobs)} />
      <Route path="/sign-in" component={Guarded(SignIn)} />
      <Route path="/users" component={Guarded(Users)} />
      <Route path="/policies" component={Guarded(Policies)} />
      <Route path="/account" component={Home} />
      <Route path="/buckets" component={Guarded(BucketList)} />
      <Route path="/buckets/:bucket" component={Guarded(BucketBrowser)} />
      <Route path="/buckets/:bucket/object" component={Guarded(ObjectPage)} />
      <Route path="/buckets/:bucket/lifecycle" component={Guarded(Lifecycle)} />
      <Route path="/login" component={Login} />
      <Route path="/enroll" component={Enroll} />
      <Route path="*" component={NotFound} />
    </Router>
  ),
  document.getElementById("root")!,
);
