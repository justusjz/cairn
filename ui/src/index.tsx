// The console (see `src/console/`): signing in as a directory user, who
// picks a permission set, with a passkey (Cairn's own directory's users) or
// at an identity source, a first passkey through a setup link, one's own
// passkeys, and
// the pages of what the signed-in identity manages: the account's buckets,
// objects, users, roles and policies, and, for its operators (whose policies
// allow `cairn:` actions), the cluster.

import { A, Navigate, Route, Router, type RouteSectionProps, useNavigate } from "@solidjs/router";
import { For, Show, createEffect, createResource, createRoot, createSignal, onCleanup } from "solid-js";
import { render } from "solid-js/web";
import { Badge, Loading, Panel, Table, Toasts, act, poll, toast } from "./components/ui";
import { ago, clock, date } from "./format";
import { api as manage, setOperatorMode } from "./api";
import { BucketBrowser, BucketList, ObjectPage } from "./pages/Buckets";
import Integrity from "./pages/Integrity";
import Jobs from "./pages/Jobs";
import Inventory from "./pages/Inventory";
import Lifecycle from "./pages/Lifecycle";
import Notifications from "./pages/Notifications";
import Overview from "./pages/Overview";
import Policies, { PolicyPage } from "./pages/Policies";
import Groups, { GroupPage } from "./pages/Groups";
import IdentityCenter, { PermissionSetPage } from "./pages/IdentityCenter";
import Organization from "./pages/Organization";
import Roles, { RolePage } from "./pages/Roles";
import Storage from "./pages/Storage";
import Topics, { TopicPage } from "./pages/Topics";
import SignIn from "./pages/SignIn";
import SwitchRole from "./pages/SwitchRole";
import Users, { UserPage } from "./pages/Users";
import "./styles.css";
import { ApiError, type Credentials, type Me, type Passkey, api } from "./session";
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
              <For each={nav(m())}>
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
      <Show when={me()?.root && me()}>{(m) => <RootBanner me={m()} logout={logout} />}</Show>
      <main>{props.children}</main>
      <Toasts />
    </>
  );
}

/** On every page while the account's root user is signed in: what that
 * means, and when the session ends. */
function RootBanner(props: { me: Me; logout: () => void }) {
  return (
    <div class="root-banner" role="status">
      <span>
        <strong>You're the account's root user.</strong> No identity policy restricts you; buckets' and topics' policies
        that deny you still do, but you can always change a bucket's policy.
        <Show when={props.me.expires_at}>{(t) => <> This session ends at {clock(t())} at the latest.</>}</Show>
      </span>
      <button class="small" onClick={props.logout}>
        Sign out
      </button>
    </div>
  );
}

/** What everyone sees: the account's buckets, users and policies (each page
 * shows what the identity's policies let it see). */
const ACCOUNT_NAV: [string, string][] = [
  ["/buckets", "Buckets"],
  ["/topics", "Topics"],
  ["/users", "Users"],
  ["/groups", "Groups"],
  ["/roles", "Roles"],
  ["/policies", "Policies"],
  ["/identity-center", "Identity Center"],
];

/** What the cluster's operators see first: the cluster. */
const CLUSTER_NAV: [string, string][] = [
  ["/", "Overview"],
  ["/storage", "Storage"],
  ["/integrity", "Integrity"],
  ["/jobs", "Jobs"],
];

/** ... and last: how people sign in. */
const OPERATOR_NAV: [string, string][] = [
  ["/organization", "Organization"],
  ["/sign-in", "Sign-in"],
];

/** The pages `m` sees: Identity Center only in the management account,
 * whose alone it is; the cluster's and the operators' to operators. */
function nav(m: Me): [string, string][] {
  const account = ACCOUNT_NAV.filter(([href]) => href !== "/identity-center" || m.identity.management);
  return m.cluster ? [...CLUSTER_NAV, ...account, ...OPERATOR_NAV] : account;
}

/** Who the session acts as: the user's name, or a directory user's
 * permission set (or its own name, until it picks one). */
function label(m: Me): string {
  if (m.switched) return m.identity.user;
  return m.directory ? (m.directory.permission_set ?? m.name) : m.identity.user;
}

/** The account the session acts in: none for a directory user until it
 * picks a permission set (and with it an account). */
function actingAccount(m: Me): { name: string; id: string } | undefined {
  if (m.directory && !m.directory.permission_set && !m.switched) return undefined;
  return { name: m.identity.account, id: m.identity.account_id };
}

/** Has the session act as who it signed in as again, and starts over
 * there (every page's data was the role's). */
async function switchBack() {
  try {
    await api.switchBack();
    location.assign("/");
  } catch (e) {
    toast(explain(e), true);
  }
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
        <span class="mono">{label(props.me)}</span>
        <Show when={actingAccount(props.me)}>
          {(a) => (
            <span class="account-chip" title={`Account ${a().id}`}>
              {a().name}
            </span>
          )}
        </Show>
        <span aria-hidden="true">▾</span>
      </button>
      <Show when={open()}>
        <div class="menu" role="menu">
          <div class="menu-head">
            Signed in as <strong>{props.me.name}</strong>
            <Show when={actingAccount(props.me)}>
              {(a) => (
                <div>
                  In account <strong>{a().name}</strong> <span class="mono">{a().id}</span>
                  <Show when={props.me.identity.management}> (management)</Show>
                </div>
              )}
            </Show>
            <Show when={props.me.switched}>
              {(s) => (
                <div>
                  As role <strong>{props.me.identity.user}</strong> until {clock(s().expires_at)}
                </div>
              )}
            </Show>
          </div>
          <hr />
          <A role="menuitem" class="menu-item" href="/account" onClick={() => setOpen(false)}>
            {props.me.root
              ? "Who you are"
              : props.me.directory
                ? props.me.directory.provider
                  ? "Permission sets and credentials"
                  : "Permission sets, credentials and passkeys"
                : "Passkeys and sign-in"}
          </A>
          <Show when={!props.me.root && (!props.me.directory || props.me.directory.permission_set)}>
            <A role="menuitem" class="menu-item" href="/switch-role" onClick={() => setOpen(false)}>
              Switch role
            </A>
          </Show>
          <Show when={props.me.switched}>
            <button role="menuitem" class="menu-item" onClick={switchBack}>
              Switch back
            </button>
          </Show>
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

/** The identity sources to sign in at, as a directory user. */
function ProviderButtons(props: { onError: (e: string) => void }) {
  const [providers] = createResource(() => api.oidcProviders().catch(() => []));
  const go = async (name: string) => {
    try {
      const { url } = await api.oidcStart(name);
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
              Sign in with {p.label}
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
  const [setup] = createResource(() => api.setup().catch(() => ({ can_sign_in: true })));
  return (
    <div class="signin">
      <Panel title="Sign in to Cairn">
        <Show when={supported()} fallback={<NoPasskeys />}>
          <Show when={setup()?.can_sign_in === false} fallback={
            <>
              <p class="subtle">Sign in with a passkey: your device asks for your fingerprint, face, PIN or security key.</p>
              <button class="primary" disabled={busy()} onClick={signIn}>
                Sign in with a passkey
              </button>
              <ProviderButtons onError={setError} />
              <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
              <p class="subtle small">
                New here? Ask an administrator for a link to set up your passkey.
              </p>
            </>
          }>
            <FirstAdmin />
          </Show>
        </Show>
      </Panel>
    </div>
  );
}

/** How to make the first person, until anyone can sign in. */
function FirstAdmin() {
  const command = "cairn directory-user create admin --admin";
  return (
    <>
      <p>No one can sign in yet. Make the first administrator on a node of the cluster, and open the link it prints to set up a passkey:</p>
      <pre class="command">{command}</pre>
      <p class="subtle small">
        In Docker Compose: <span class="mono">docker compose exec cairn {command}</span>. Everyone after that is made in
        the console.
      </p>
    </>
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
      <Panel title="Set up your sign-in">
        <Show when={supported()} fallback={<NoPasskeys />}>
          <Show when={ceremony()} fallback={<Loading error={ceremony.error && (ceremony.error as Error).message} />}>
            {(c) => (
              <form onSubmit={enroll}>
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
 * anyone else, and a directory user that hasn't picked a permission set
 * yet its permission sets. */
function Start() {
  return (
    <Show when={!(me()?.directory && !me()?.directory?.permission_set)} fallback={<Navigate href="/account" />}>
      <Show when={me()?.cluster} fallback={<Navigate href="/buckets" />}>
        <Overview />
      </Show>
    </Show>
  );
}

function Home() {
  return (
    <SignedIn>
      {(m) => (
        <Show when={!m.root} fallback={<RootHome me={m} />}>
          <DirectoryHome me={m} />
        </Show>
      )}
    </SignedIn>
  );
}

/** A directory user's own page: who its identity source says it is, the
 * permission sets it may use and the accounts it may use them in (to switch
 * between), and credentials of the one it uses, for the CLI. */
function DirectoryHome(props: { me: Me }) {
  const navigate = useNavigate();
  const d = () => props.me.directory!;
  const [credentials, setCredentials] = createSignal<Credentials>();
  const choose = async (name: string, account_id: string) => {
    try {
      setMe(await api.choosePermissionSet(name, account_id));
      setCredentials(undefined);
      toast(`Using ${name}`);
      navigate("/");
    } catch (e) {
      toast(explain(e), true);
    }
  };
  const inUse = (set: { name: string; account_id: string }) =>
    set.name === d().permission_set && set.account_id === d().permission_set_account_id;
  const getCredentials = async () => {
    try {
      setCredentials(await api.directoryCredentials());
    } catch (e) {
      toast(explain(e), true);
    }
  };
  const exports = (c: Credentials) =>
    `export AWS_ACCESS_KEY_ID=${c.access_key_id}\nexport AWS_SECRET_ACCESS_KEY=${c.secret_access_key}\nexport AWS_SESSION_TOKEN=${c.session_token}`;
  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast("Copied");
    } catch {
      toast("Copying isn't allowed here: select the text instead", true);
    }
  };
  return (
    <>
      <div class="page-head">
        <h1>{props.me.name}</h1>
        <span class="subtle small">
          {d().provider_label ? `signed in at ${d().provider_label}` : "signed in with a passkey"}
        </span>
      </div>
      <Panel title="Permission sets">
        <Table
          count={d().permission_sets.length}
          empty="None is assigned to you anymore."
          columns={["Account", "Name", "Description", "Sessions", ""]}
        >
          <For each={d().permission_sets}>
            {(set) => (
              <tr>
                <td>
                  {set.account}
                  <div class="subtle small mono">{set.account_id}</div>
                </td>
                <td class="mono">
                  {set.name}{" "}
                  <Show when={inUse(set)}>
                    <Badge tone="ok">in use</Badge>
                  </Show>
                </td>
                <td>{set.description || <span class="subtle">none</span>}</td>
                <td>{Math.round(set.session_duration / 360) / 10} h</td>
                <td class="actions">
                  <Show when={!inUse(set)}>
                    <button class="small primary" onClick={() => choose(set.name, set.account_id)}>
                      Use
                    </button>
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </Table>
        <p class="subtle small">
          What you may do here is what the permission set you use allows: you act as a session of its role,{" "}
          <Show when={props.me.identity.arn} fallback={<>once you pick one</>}>
            <span class="mono">{props.me.identity.arn}</span>
          </Show>
          . An administrator assigns them to you, or to your groups, on the Identity Center page.
        </p>
      </Panel>
      <Show when={d().permission_set}>
        <Panel title="Credentials for the CLI">
          <p class="subtle small">
            Temporary credentials of the permission set's role, for the AWS CLI and SDKs, valid as long as its sessions
            last. Anyone who has them acts as you until they expire.
          </p>
          <Show
            when={credentials()}
            fallback={
              <button class="small" onClick={getCredentials}>
                Get credentials
              </button>
            }
          >
            {(c) => (
              <>
                <pre class="credentials">{exports(c())}</pre>
                <p class="subtle small">They expire at {clock(c().expiration)}.</p>
                <button class="small" onClick={() => copy(exports(c()))}>
                  Copy
                </button>
              </>
            )}
          </Show>
        </Panel>
      </Show>
      <Panel title="Who you are">
        <Table count={1} columns={["User name", "Source", "Subject", "E-mail", "Groups"]}>
          <tr>
            <td class="mono">{d().user_name}</td>
            <td>{d().provider_label ?? "Cairn's own directory"}</td>
            <td class="mono small">{d().subject ?? <span class="subtle">none</span>}</td>
            <td>{d().email ?? <span class="subtle">none given</span>}</td>
            <td>
              <For each={d().groups} fallback={<span class="subtle">none</span>}>
                {(g) => <span class="chip mono">{g}</span>}
              </For>
            </td>
          </tr>
        </Table>
        <Show
          when={d().provider_label}
          fallback={
            <p class="subtle small">
              You're a user of Cairn's own directory: you sign in with your passkeys, so your session counts as
              multi-factor (<span class="mono">aws:MultiFactorAuthPresent</span>). Your console session ends at{" "}
              {clock(props.me.expires_at ?? 0)} at the latest.
            </p>
          }
        >
          <p class="subtle small">
            You're a directory user: {d().provider_label} vouches for you, with these groups, as of when you signed
            in. You have no passkeys or access keys of your own here. A session signed in at an identity source isn't
            multi-factor (<span class="mono">aws:MultiFactorAuthPresent</span> is false). Your console session ends
            at {clock(props.me.expires_at ?? 0)} at the latest.
          </p>
        </Show>
      </Panel>
      <Show when={!d().provider}>
        <Passkeys passkeys={props.me.passkeys} />
      </Show>
    </>
  );
}

/** Who the account's root user is: no login, so nothing of its own to set. */
function RootHome(props: { me: Me }) {
  return (
    <>
      <div class="page-head">
        <h1>The root user</h1>
      </div>
      <Panel title="Who you are">
        <Table count={1} columns={["As", "ARN"]}>
          <tr>
            <td class="mono">root</td>
            <td class="mono small">{props.me.identity.arn}</td>
          </tr>
        </Table>
        <p class="subtle small">
          You're the account itself, as AWS's root user: no identity policy, permissions boundary or group restricts
          you. A bucket's or topic's policy that denies you (everyone, or the account) still does, but you can always
          read, change and delete a bucket's policy. You signed in with a link from the command line, so your session
          isn't multi-factor (<span class="mono">aws:MultiFactorAuthPresent</span> is false). It has no passkeys: the
          only way in is another link (<span class="mono">cairn account root-link</span> on a node).
        </p>
      </Panel>
    </>
  );
}

/** Signing in as the account's root user, with a link from the command line
 * (`cairn account root-link`): the button uses it up. */
function RootSignIn() {
  const navigate = useNavigate();
  const token = location.hash.slice(1);
  // The token stays out of the history and the address bar once read.
  history.replaceState(null, "", location.pathname);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | undefined>(token ? undefined : "This link has no token.");
  const signIn = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setMe(await api.rootSignIn(token));
      navigate("/");
    } catch (e) {
      setError(explain(e));
      setBusy(false);
    }
  };
  return (
    <div class="signin">
      <Panel title="Sign in as the root user">
        <p>
          This link signs you in as the account's root user, whom no identity policy restricts: for getting back in
          when policies lock everyone else out. It works once, and the session lasts an hour at most.
        </p>
        <Show when={me()}>
          {(m) => (
            <p class="subtle small">
              You're signed in as <span class="mono">{m().name}</span>; this replaces that session.
            </p>
          )}
        </Show>
        <button class="primary" disabled={busy() || !token} onClick={signIn}>
          Sign in as root
        </button>
        <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
        <p class="subtle small">
          If it doesn't work anymore, make another on a node: <span class="mono">cairn account root-link</span>.
        </p>
      </Panel>
    </div>
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
                <button
                  class="small danger"
                  disabled={props.passkeys.length <= 1}
                  title={props.passkeys.length <= 1 ? "Your last way to sign in" : ""}
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
      <Route path="/organization" component={Guarded(Organization)} />
      <Route path="/users" component={Guarded(Users)} />
      <Route path="/users/:name" component={Guarded(UserPage)} />
      <Route path="/groups" component={Guarded(Groups)} />
      <Route path="/groups/:name" component={Guarded(GroupPage)} />
      <Route path="/roles" component={Guarded(Roles)} />
      <Route path="/roles/:name" component={Guarded(RolePage)} />
      <Route path="/policies" component={Guarded(Policies)} />
      <Route path="/policies/:name" component={Guarded(PolicyPage)} />
      <Route path="/identity-center" component={Guarded(IdentityCenter)} />
      <Route path="/identity-center/:name" component={Guarded(PermissionSetPage)} />
      <Route path="/account" component={Home} />
      <Route path="/switch-role" component={Guarded(SwitchRole)} />
      <Route path="/buckets" component={Guarded(BucketList)} />
      <Route path="/buckets/:bucket" component={Guarded(BucketBrowser)} />
      <Route path="/buckets/:bucket/object" component={Guarded(ObjectPage)} />
      <Route path="/buckets/:bucket/lifecycle" component={Guarded(Lifecycle)} />
      <Route path="/buckets/:bucket/notifications" component={Guarded(Notifications)} />
      <Route path="/buckets/:bucket/inventory" component={Guarded(Inventory)} />
      <Route path="/topics" component={Guarded(Topics)} />
      <Route path="/topics/:name" component={Guarded(TopicPage)} />
      <Route path="/login" component={Login} />
      <Route path="/enroll" component={Enroll} />
      <Route path="/root" component={RootSignIn} />
      <Route path="*" component={NotFound} />
    </Router>
  ),
  document.getElementById("root")!,
);
