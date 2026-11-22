// A bucket's incomplete multipart uploads: what ListMultipartUploads lists,
// with each one's parts and bytes, which take up storage until the upload is
// completed or aborted, and when a lifecycle rule aborts it, if one does.

import { A, useParams } from "@solidjs/router";
import { For, Show, createEffect, createSignal, on } from "solid-js";
import { type UploadInfo, type UploadList, api } from "../api";
import { Loading, Panel, Table, act, toast } from "../components/ui";
import { ago, bytes, date, now, num, plural } from "../format";
import { bucketUrl } from "./Buckets";

export default function Uploads() {
  const params = useParams();
  const bucket = () => params.bucket ?? "";
  const [list, setList] = createSignal<UploadList>();
  const [error, setError] = createSignal<string>();
  const [busy, setBusy] = createSignal(false);

  const load = async () => {
    try {
      setList(await api.uploads(bucket()));
      setError(undefined);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  createEffect(on(bucket, load));

  const more = async () => {
    const l = list();
    if (!l?.next) return;
    const page = await act(() => api.uploads(bucket(), l.next!));
    if (page) setList({ ...page.value, uploads: [...l.uploads, ...page.value.uploads] });
  };

  const abort = async (u: UploadInfo) => {
    if (!confirm(`Abort the upload of "${u.key}"? Its ${plural(u.parts, "part")} (${bytes(u.bytes)}) are deleted.`)) return;
    if (await act(() => api.abortUpload(bucket(), u.key, u.upload_id), `Aborted the upload of ${u.key}`)) load();
  };

  const abortAll = async () => {
    const uploads = list()?.uploads ?? [];
    const total = uploads.reduce((sum, u) => sum + u.bytes, 0);
    if (!confirm(`Abort all ${plural(uploads.length, "upload")} listed here? Their parts (${bytes(total)}) are deleted.`)) return;
    setBusy(true);
    let aborted = 0;
    let failed: string | undefined;
    for (const u of uploads) {
      try {
        await api.abortUpload(bucket(), u.key, u.upload_id);
        aborted++;
      } catch (e) {
        failed ??= (e as Error).message;
      }
    }
    setBusy(false);
    if (failed) toast(`Aborted ${plural(aborted, "upload")}; others failed: ${failed}`, true);
    else toast(`Aborted ${plural(aborted, "upload")}`);
    load();
  };

  return (
    <>
      <h1>
        Multipart uploads of <span class="mono">{bucket()}</span>
      </h1>
      <div class="crumbs">
        <A href="/buckets">Buckets</A>
        <span class="sep">/</span>
        <A href={bucketUrl(bucket())}>{bucket()}</A>
        <span class="sep">/</span>
        <span>uploads</span>
      </div>
      <p class="subtle">
        Uploads begun but neither completed nor aborted. Their parts take up storage until then. A lifecycle rule
        that aborts incomplete uploads makes each due at midnight UTC, the given number of days after the one
        following its start; the bucket's next daily sweep after that aborts it. Aborting an upload here deletes
        its parts at once, and a client still sending parts to it gets an error.
      </p>
      <Show when={list()} fallback={<Loading error={error()} />}>
        {(l) => (
          <>
            <Panel
              title={
                <>
                  {plural(l().count, "upload")} in progress · {bytes(l().bytes)}
                </>
              }
            >
              <Table
                count={l().uploads.length}
                empty="No uploads in progress."
                columns={["Key", "Started", { label: "Parts", num: true }, { label: "Size", num: true }, "Lifecycle", ""]}
              >
                <For each={l().uploads}>{(u) => <Row upload={u} abort={() => abort(u)} disabled={busy()} />}</For>
              </Table>
            </Panel>
            <div class="toolbar">
              <Show when={l().next}>
                <button onClick={more}>Show more</button>
              </Show>
              <span class="spacer" />
              <button onClick={load} disabled={busy()}>
                Refresh
              </button>
              <Show when={l().uploads.length > 1}>
                <button class="danger" onClick={abortAll} disabled={busy()}>
                  {busy() ? "Aborting…" : `Abort all ${l().next ? "listed " : ""}(${num(l().uploads.length)})`}
                </button>
              </Show>
            </div>
          </>
        )}
      </Show>
    </>
  );
}

function Row(props: { upload: UploadInfo; abort: () => void; disabled: boolean }) {
  const u = () => props.upload;
  return (
    <tr>
      <td>
        <span class="mono">{u().key}</span>
        <div class="subtle small mono" title="Upload ID">
          {u().upload_id}
        </div>
      </td>
      <td>
        <span title={date(u().initiated)}>{ago(u().initiated)}</span>
        <Show when={u().initiator}>
          {(who) => (
            <div class="subtle small mono" title={who()}>
              by {who().split(":").pop()}
            </div>
          )}
        </Show>
      </td>
      <td class="num">{num(u().parts)}</td>
      <td class="num">{bytes(u().bytes)}</td>
      <td>
        <Show when={u().abort_date} fallback={<span class="subtle">kept until completed or aborted</span>}>
          {(d) => (
            <>
              {d() <= now() ? `due since ${date(d())}` : `due ${date(d())}`}
              <div class="subtle small">
                {d() <= now() ? "aborted by the next sweep · " : ""}rule <span class="mono">{u().abort_rule}</span>
              </div>
            </>
          )}
        </Show>
      </td>
      <td class="num">
        <button class="small danger" onClick={props.abort} disabled={props.disabled}>
          Abort
        </button>
      </td>
    </tr>
  );
}
