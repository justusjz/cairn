// Small building blocks shared by the pages.

import { For, type JSX, Show, createSignal, onCleanup, onMount } from "solid-js";

/** Data fetched now and every `every` ms after (paused while the tab is
 * hidden), until the calling component goes away. Keeps the last data on a
 * failed refresh, and reports the failure. */
export function poll<T>(fetch: () => Promise<T>, every?: number) {
  const [data, setData] = createSignal<T>();
  const [error, setError] = createSignal<string>();
  let alive = true;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const refresh = async () => {
    clearTimeout(timer);
    try {
      const value = await fetch();
      if (!alive) return;
      setData(() => value);
      setError(undefined);
    } catch (e) {
      if (alive) setError((e as Error).message);
    }
    if (alive && every) timer = setTimeout(tick, every);
  };
  const tick = () => {
    if (document.hidden) timer = setTimeout(tick, 1000);
    else refresh();
  };
  refresh();
  onCleanup(() => {
    alive = false;
    clearTimeout(timer);
  });
  return { data, error, refresh };
}

// ── Toasts ──

const [toasts, setToasts] = createSignal<{ id: number; message: string; error: boolean }[]>([]);
let nextToast = 0;

export function toast(message: string, error = false) {
  const id = nextToast++;
  setToasts((t) => [...t, { id, message, error }]);
  setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), error ? 7000 : 3500);
}

/** Runs an action, telling the user how it went. Resolves to its result
 * wrapped (an action may have none, e.g. a 204), or undefined if it failed. */
export async function act<T>(fn: () => Promise<T>, success?: string): Promise<{ value: T } | undefined> {
  try {
    const value = await fn();
    if (success) toast(success);
    return { value };
  } catch (e) {
    toast((e as Error).message, true);
    return undefined;
  }
}

export function Toasts() {
  return (
    <div class="toasts" aria-live="polite">
      <For each={toasts()}>{(t) => <div class={"toast" + (t.error ? " error" : "")}>{t.message}</div>}</For>
    </div>
  );
}

// ── Layout ──

export type Tone = "ok" | "warn" | "bad" | "accent" | "";

export function Card(props: { label: string; value: JSX.Element; note?: JSX.Element; tone?: Tone }) {
  return (
    <div class={"card " + (props.tone ?? "")}>
      <div class="label">{props.label}</div>
      <div class="value">{props.value}</div>
      <Show when={props.note}>
        <div class="note">{props.note}</div>
      </Show>
    </div>
  );
}

export function Panel(props: { title?: JSX.Element; note?: JSX.Element; children: JSX.Element }) {
  return (
    <section class="panel">
      <Show when={props.title}>
        <h2>
          {props.title} <span class="subtle">{props.note}</span>
        </h2>
      </Show>
      {props.children}
    </section>
  );
}

export function Badge(props: { tone?: Tone; children: JSX.Element }) {
  return <span class={"badge " + (props.tone ?? "")}>{props.children}</span>;
}

export function LiveDot(props: { live: boolean }) {
  return <span class={"live-dot" + (props.live ? "" : " down")} />;
}

/** How full something is, coloured once it gets full. */
export function Bar(props: { used: number; total: number; warnAt?: number; badAt?: number }) {
  const fraction = () => (props.total ? Math.min(1, props.used / props.total) : 0);
  const tone = () => (fraction() >= (props.badAt ?? 0.92) ? "bad" : fraction() >= (props.warnAt ?? 0.8) ? "warn" : "");
  return (
    <div class={"bar " + tone()}>
      <span style={{ width: (fraction() * 100).toFixed(1) + "%" }} />
    </div>
  );
}

export type Column = string | { label: string; num?: boolean };

/** A table, with a row saying so when it's empty. */
export function Table(props: { columns: Column[]; empty?: string; children: JSX.Element; count: number }) {
  return (
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <For each={props.columns}>
              {(c) => (typeof c === "string" ? <th>{c}</th> : <th class={c.num ? "num" : ""}>{c.label}</th>)}
            </For>
          </tr>
        </thead>
        <tbody>
          <Show
            when={props.count > 0}
            fallback={
              <tr>
                <td class="empty" colspan={props.columns.length}>
                  {props.empty ?? "Nothing here."}
                </td>
              </tr>
            }
          >
            {props.children}
          </Show>
        </tbody>
      </table>
    </div>
  );
}

/** The page's state while its data loads, or if it couldn't. */
export function Loading(props: { error?: string }) {
  return (
    <Show when={props.error} fallback={<div class="subtle">Loading…</div>}>
      <Panel title="Something went wrong">
        <p>{props.error}</p>
      </Panel>
    </Show>
  );
}

/** A modal showing a role's new secret, which is shown only this once. */
export function SecretDialog(props: { name: string; secret: string; onClose: () => void }) {
  let dialog!: HTMLDialogElement;
  let input!: HTMLInputElement;
  onMount(() => {
    dialog.showModal();
    input.select();
  });
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.secret);
      toast("Copied");
    } catch {
      input.select();
    }
  };
  return (
    <dialog ref={dialog} onClose={() => props.onClose()}>
      <h2>
        Secret for <span class="mono">{props.name}</span>
      </h2>
      <p class="subtle">
        Store it now: it isn't shown again. Clients use the role's name as access key ID and this as secret access key.
      </p>
      <div class="secret">
        <input ref={input} type="text" readOnly value={props.secret} />
        <button onClick={copy}>Copy</button>
      </div>
      <div class="buttons">
        <button class="primary" onClick={() => dialog.close()}>
          Done
        </button>
      </div>
    </dialog>
  );
}
