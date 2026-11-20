// The KMS's root key, as the cluster's nodes see it.

import { For, Match, Show, Switch } from "solid-js";
import type { Cluster } from "../api";
import { ago } from "../format";
import { Badge, Panel, Table, toast } from "./ui";

/** The KMS's root key, which wraps every KMS key's material (and the
 * backup's and tiers' keys), as each node sees it: a file, or a key of
 * OpenBao's, and then whether the node reaches OpenBao, how its logins
 * went, and the public key OpenBao is to trust. The operator's: on the
 * Storage page. */
export function KmsPanel(props: { cluster: Cluster; refresh: () => void }) {
  const nodes = () => props.cluster.nodes.filter((n) => n.stats?.kms);
  const kms = () => nodes()[0]?.stats?.kms;
  const roots = () => new Set(nodes().map((n) => n.stats?.kms?.root)).size;
  const keys = () => new Set(nodes().map((n) => n.stats?.kms?.public_key)).size;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(kms()?.public_key ?? "");
      toast("Copied");
    } catch {
      toast("Couldn't copy; select the key instead", true);
    }
  };
  return (
    <Panel title="KMS" note={kms()?.address ?? undefined}>
      <Show
        when={kms()}
        fallback={
          <p class="subtle">
            No KMS is configured, so SSE-KMS, SSE-S3 and the KMS's API are refused. Give the nodes a root key: a file (
            <span class="mono">--kms-root-key-file</span>), or a key of OpenBao's (
            <span class="mono">--kms-address</span>, <span class="mono">--kms-jwt-key</span>).
          </p>
        }
      >
        {(k) => (
          <>
            <Show when={roots() > 1}>
              <Badge tone="bad">nodes have different kinds of root keys: give every node the cluster's</Badge>
            </Show>
            <Switch>
              <Match when={k().root === "file"}>
                <p class="subtle small">
                  The KMS's keys, and the backup's and tiers' keys, are wrapped by a root key from a file (
                  <span class="mono">--kms-root-key-file</span>), the same on every node. Keep a copy of it apart
                  from the cluster: without it, nothing encrypted is readable.
                </p>
              </Match>
              <Match when={k().root === "openbao"}>
                <p class="subtle small">
                  The KMS's keys, and the backup's and tiers' keys, are wrapped by the Transit key{" "}
                  <span class="mono">{k().transit_key}</span> in OpenBao, which never leaves it. Cairn logs in as
                  itself (the subject <span class="mono">cairn</span>) through OpenBao's JWT auth method at{" "}
                  <span class="mono">auth/{k().auth_mount}</span> (role <span class="mono">{k().auth_role}</span>),
                  which is to trust this public key (<span class="mono">jwt_validation_pubkeys</span>), and whose
                  tokens may <span class="mono">encrypt</span> and <span class="mono">decrypt</span> with that key.
                </p>
                <div class="pem">{(k().public_key ?? "").trim()}</div>
                <button class="small" onClick={copy}>
                  Copy public key
                </button>
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
                            <Show
                              when={s().last_login}
                              fallback={<span class="subtle">none since it started</span>}
                            >
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
                  A node logs in when it first needs a key's material, and keeps what it unwrapped for an hour after
                  its last use.
                </p>
              </Match>
            </Switch>
          </>
        )}
      </Show>
    </Panel>
  );
}
