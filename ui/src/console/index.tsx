// The console: where an account's people sign in with passkeys (see
// `src/console/`): signing in, a first passkey through an enrollment link,
// one's own passkeys, and the buckets and objects, as the user. Those are
// the dashboard's pages, talking to the same API, which the console serves
// as its user (`useConsoleApi`).

import { A, Navigate, Route, Router, type RouteSectionProps, useNavigate } from "@solidjs/router";
import { For, Show, createResource, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { Badge, Loading, Panel, Table, Toasts, act, toast } from "../components/ui";
import { ago, date } from "../format";
import { useConsoleApi } from "../api";
import { BucketBrowser, BucketList, ObjectPage } from "../pages/Buckets";
import Lifecycle from "../pages/Lifecycle";
import "../styles.css";
import { ApiError, type Me, type Passkey, api } from "./api";
import { authenticate, deviceName, explain, register, supported } from "./webauthn";

useConsoleApi();

/** Who's signed in: `null` if no one, undefined while asking. */
const [me, { refetch: refreshMe, mutate: setMe }] = createResource<Me | null>(async () => {
  try {
    return await api.me();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
});

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
            <A href="/buckets" activeClass="active">
              Buckets
            </A>
            <A href="/account" activeClass="active">
              Account
            </A>
          </Show>
        </nav>
        <Show when={me()}>
          {(m) => (
            <div class="whoami">
              <span class="mono">{m().name}</span>
              <button class="small" onClick={logout}>
                Sign out
              </button>
            </div>
          )}
        </Show>
      </header>
      <main>{props.children}</main>
      <Toasts />
    </>
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
  const [error, setError] = createSignal<string>();
  const signIn = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const ceremony = await api.loginOptions();
      const credential = await authenticate(ceremony.options);
      setMe(await api.login(ceremony.challenge_id, credential));
      navigate("/buckets");
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
          <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
          <p class="subtle small">
            No passkey yet? Ask an administrator for an enrollment link.
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
      <Panel title="Set up your passkey">
        <Show when={supported()} fallback={<NoPasskeys />}>
          <Show when={ceremony()} fallback={<Loading error={ceremony.error && (ceremony.error as Error).message} />}>
            {(c) => (
              <form onSubmit={enroll}>
                <p>
                  Welcome, <span class="mono">{c().user}</span>. Make a passkey for this console: your device keeps it,
                  and asks for your fingerprint, face, PIN or security key when you sign in. There's no password.
                </p>
                <label class="field">
                  Name it
                  <input type="text" required maxLength={64} value={name()} onInput={(e) => setName(e.currentTarget.value)} />
                </label>
                <button class="primary" type="submit" disabled={busy()}>
                  Make a passkey
                </button>
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

function Home() {
  return (
    <SignedIn>
      {(m) => (
        <>
          <div class="page-head">
            <h1>{m.name}</h1>
          </div>
          <Panel title="You">
            <p>
              <span class="mono">{m.arn}</span>{" "}
              <Show when={m.admin}>
                <Badge tone="accent">admin</Badge>
              </Show>
            </p>
            <p class="subtle small">
              Policies name you by this ARN. What you may do here is what your access keys may do over S3: your grants,
              admin rights and policies, and the buckets' policies, decide both.
            </p>
          </Panel>
          <Passkeys passkeys={m.passkeys} />
        </>
      )}
    </SignedIn>
  );
}

function Passkeys(props: { passkeys: Passkey[] }) {
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
                <button class="small danger" disabled={props.passkeys.length <= 1} title={props.passkeys.length <= 1 ? "Your last passkey" : ""} onClick={() => remove(p)}>
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
      <Route path="/" component={() => <Navigate href="/buckets" />} />
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
