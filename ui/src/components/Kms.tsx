// The KMS (OpenBao) that SSE-KMS keys are in, as the cluster's nodes see it.

import { For, Show } from "solid-js";
import { type Cluster, api } from "../api";
import { ago } from "../format";
import { Badge, Panel, Table, act, toast } from "./ui";

/** The KMS (OpenBao) that SSE-KMS keys are in, as each node sees it: what
 * it's to trust (Cairn's public key), whether it's reachable, and how the
 * node's logins as users went. The operator's: on the Storage page. */
export function KmsPanel(props: { cluster: Cluster; refresh: () => void }) {
  const nodes = () => props.cluster.nodes.filter((n) => n.stats?.kms);
  const kms = () => nodes()[0]?.stats?.kms;
  const keys = () => new Set(nodes().map((n) => n.stats?.kms?.public_key)).size;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(kms()?.public_key ?? "");
      toast("Copied");
    } catch {
      toast("Couldn't copy; select the key instead", true);
    }
  };
  const identify = async () => {
    await act(() => api.identifyUsers(), "Every user has its identity in OpenBao");
    props.refresh();
  };
  return (
    <Panel title="KMS" note={kms()?.address}>
      <Show
        when={kms()}
        fallback={
          <p class="subtle">
            No KMS is configured, so SSE-KMS requests are refused. Set <span class="mono">--kms-address</span> and{" "}
            <span class="mono">--kms-jwt-key</span> to keep keys in OpenBao.
          </p>
        }
      >
        {(k) => (
          <>
            <p class="subtle small">
              SSE-KMS keys are in OpenBao's Transit engines. Cairn uses them as the user that asks: it logs in as each
              user through OpenBao's JWT auth method at <span class="mono">auth/{k().auth_mount}</span> (role{" "}
              <span class="mono">{k().auth_role}</span>), which is to trust this public key (
              <span class="mono">jwt_validation_pubkeys</span>). Key owners then grant keys to users' entities.
            </p>
            <div class="pem">{k().public_key.trim()}</div>
            <button class="small" onClick={copy}>
              Copy public key
            </button>
            <Show when={k().sse_s3_key}>
              {(key) => (
                <p class="small">
                  SSE-S3 uses the key <span class="mono">{key()}</span> as Cairn itself, whose identity in OpenBao is{" "}
                  <Show when={k().cairn_entity} fallback={<Badge tone="warn">pending</Badge>}>
                    {(entity) => <span class="mono">{entity()}</span>}
                  </Show>
                  : grant it <span class="mono">datakey/plaintext</span> and <span class="mono">decrypt</span> on that key.
                </p>
              )}
            </Show>
            <Show when={keys() > 1}>
              <Badge tone="bad">nodes sign with different keys: give every node the same --kms-jwt-key</Badge>
            </Show>
            <Table count={nodes().length} columns={["Node", "OpenBao", "Last login"]}>
              <For each={nodes()}>
                {(n) => {
                  const s = () => n.stats!.kms!;
                  return (
                    <tr>
                      <td class="mono">#{n.id}</td>
                      <td>
                        <Show
                          when={s().reachable}
                          fallback={
                            <>
                              <Badge tone="bad">unreachable</Badge>
                              <div class="subtle small">{s().error}</div>
                            </>
                          }
                        >
                          <Show when={!s().sealed} fallback={<Badge tone="bad">sealed</Badge>}>
                            <Badge tone="ok">{s().standby ? "standby" : "active"}</Badge>
                          </Show>{" "}
                          <span class="subtle">{s().version}</span>
                        </Show>
                      </td>
                      <td>
                        <Show when={s().last_login} fallback={<span class="subtle">none since it started</span>}>
                          {(l) => (
                            <>
                              <Show when={l().error} fallback={<Badge tone="ok">ok</Badge>}>
                                <Badge tone="bad">failed</Badge>
                              </Show>{" "}
                              <span class="subtle">{ago(l().at)}</span>
                              <Show when={l().error}>{(e) => <div class="small">{e()}</div>}</Show>
                              <Show when={l().error && s().last_success}>
                                <div class="subtle small">last worked {ago(s().last_success)}</div>
                              </Show>
                            </>
                          )}
                        </Show>
                      </td>
                    </tr>
                  );
                }}
              </For>
            </Table>
            <p class="subtle small">
              Nodes log in for new users once a minute.{" "}
              <button class="small" onClick={identify}>
                Log in now
              </button>
            </p>
          </>
        )}
      </Show>
    </Panel>
  );
}
