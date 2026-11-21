// Signing in the AWS CLI and SDKs at Cairn's access portal (`aws sso
// login`; see `src/console/portal.rs`): the pages where the signed-in
// directory user allows a program's sign-in, or denies it. A browser sign-in
// (the CLI's default) comes here from the program, and goes back to it; a
// device sign-in (`--use-device-code`) has the person type, or check, the
// code the program shows.

import { useParams } from "@solidjs/router";
import { Match, Show, Switch, createResource, createSignal } from "solid-js";
import { Loading, Panel } from "../components/ui";
import { type Me, type SignInRequest, api } from "../session";
import { explain } from "../webauthn";

/** What a person allows: the program, as itself, for how long. */
function Asking(props: { me: Me; request: SignInRequest }) {
  return (
    <>
      <p>
        <strong class="mono">{props.request.client_name}</strong> asks to sign in as you,{" "}
        <strong>{props.me.name}</strong>.
      </p>
      <p>
        If you allow it, it can get temporary credentials of every permission set assigned to you, in every account
        it's assigned in, for {props.request.session_hours} hours, or until it signs out (
        <span class="mono">aws sso logout</span>).
      </p>
      <p class="subtle small">
        Allow it only if you started it yourself, just now: <span class="mono">aws sso login</span>, say. If you didn't,
        deny it.
      </p>
    </>
  );
}

/** Allow and Deny, and what came of it. */
function Decide(props: { id: string; onDecided: (allowed: boolean, redirect?: string | null) => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const decide = async (allow: boolean) => {
    setBusy(true);
    setError(undefined);
    try {
      const { redirect } = await api.decideSignIn(props.id, allow);
      props.onDecided(allow, redirect);
    } catch (e) {
      setError(explain(e));
      setBusy(false);
    }
  };
  return (
    <>
      <div class="decide">
        <button class="primary" disabled={busy()} onClick={() => decide(true)}>
          Allow
        </button>
        <button disabled={busy()} onClick={() => decide(false)}>
          Deny
        </button>
      </div>
      <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
    </>
  );
}

function Done(props: { allowed: boolean }) {
  return (
    <Show
      when={props.allowed}
      fallback={<p>Denied: the program doesn't get in. You can close this window.</p>}
    >
      <p>Allowed: the program carries on, signed in as you. You can close this window.</p>
    </Show>
  );
}

/** Root users have no permission sets, so they allow no one. */
function NotADirectoryUser() {
  return (
    <p class="error-text">
      Only a directory user signs programs in, with the permission sets assigned to them. Sign out, and sign in as
      yourself.
    </p>
  );
}

/** A browser's sign-in (`/sso/authorize/<id>`), which the program sent here:
 * allowed or denied, the browser goes back to the program. */
export function AuthorizeSignIn(props: { me: Me }) {
  const params = useParams();
  const [request] = createResource(() => params.id, (id) => api.signInRequest(id));
  const [done, setDone] = createSignal<boolean>();
  const decided = (allowed: boolean, redirect?: string | null) => {
    setDone(allowed);
    // Back to the program, on this computer, which shows how it went.
    if (redirect) location.assign(redirect);
  };
  return (
    <div class="signin">
      <Panel title="Sign in a program">
        <Show when={props.me.directory} fallback={<NotADirectoryUser />}>
          <Switch>
            <Match when={done() !== undefined}>
              <Done allowed={done()!} />
            </Match>
            <Match when={request.error}>
              <p class="error-text">{explain(request.error)}</p>
            </Match>
            <Match when={request()}>
              {(r) => (
                <>
                  <Asking me={props.me} request={r()} />
                  <Decide id={r().id} onDecided={decided} />
                </>
              )}
            </Match>
            <Match when={true}>
              <Loading />
            </Match>
          </Switch>
        </Show>
      </Panel>
    </div>
  );
}

/** A device's sign-in (`/device`, with the code as `?user_code=` if the
 * program sent the person here itself): the person checks the code against
 * what the program shows, or types it. */
export function DeviceSignIn(props: { me: Me }) {
  const [code, setCode] = createSignal(new URLSearchParams(location.search).get("user_code") ?? "");
  const [request, setRequest] = createSignal<SignInRequest>();
  const [done, setDone] = createSignal<boolean>();
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const look = async (e: SubmitEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      setRequest(await api.deviceSignInRequest(code()));
    } catch (e) {
      setError(explain(e));
    }
    setBusy(false);
  };
  return (
    <div class="signin">
      <Panel title="Sign in a program">
        <Show when={props.me.directory} fallback={<NotADirectoryUser />}>
          <Switch>
            <Match when={done() !== undefined}>
              <Done allowed={done()!} />
            </Match>
            <Match when={request()}>
              {(r) => (
                <>
                  <p>Check that the program shows this code:</p>
                  <pre class="command user-code">{r().user_code}</pre>
                  <Asking me={props.me} request={r()} />
                  <Decide id={r().id} onDecided={(allowed) => setDone(allowed)} />
                </>
              )}
            </Match>
            <Match when={true}>
              <form onSubmit={look}>
                <p>Enter the code the program shows (as BCDF-GHJK):</p>
                <input
                  type="text"
                  class="mono user-code-input"
                  value={code()}
                  onInput={(e) => setCode(e.currentTarget.value)}
                  autocomplete="off"
                  autocapitalize="characters"
                  spellcheck={false}
                  aria-label="Code"
                />
                <button class="primary" type="submit" disabled={busy() || !code().trim()}>
                  Next
                </button>
                <Show when={error()}>{(e) => <p class="error-text">{e()}</p>}</Show>
              </form>
            </Match>
          </Switch>
        </Show>
      </Panel>
    </div>
  );
}
