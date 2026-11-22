// An account, named rather than shown by its bare ID: the names the session
// may know of (`/account-names`: the organization's, for who may list its
// accounts; else its own), fetched once per identity the session acts as
// and shared by every page.

import { Show, createResource, createRoot, createSignal } from "solid-js";
import { api } from "../api";

const [identity, setIdentity] = createSignal<string>();

/** Has the names fetched for who the session acts as now (its ARN; none
 * while no one's signed in). */
export const actingAs = (arn: string | undefined) => setIdentity(arn);

const [names] = createRoot(() =>
  createResource(identity, async () => {
    try {
      return new Map((await api.accountNames()).map((a) => [a.id, a.name]));
    } catch {
      return new Map<string, string>();
    }
  }),
);

/** Account `id`'s name, if the session may know it. */
export function accountName(id: string): string | undefined {
  return names()?.get(id);
}

/** Account `id`: its name, with its ID after it, small (or in a tooltip, if
 * `compact`); just its ID when its name isn't known. */
export function AccountName(props: { id: string; compact?: boolean }) {
  return (
    <Show when={accountName(props.id)} fallback={<span class="mono small">{props.id}</span>}>
      {(name) => (
        <Show
          when={!props.compact}
          fallback={
            <span title={props.id}>
              {name()}
            </span>
          }
        >
          {name()} <span class="mono small subtle">{props.id}</span>
        </Show>
      )}
    </Show>
  );
}
