// Request metrics of several nodes, added up. Every node numbers its history
// slots the same way (Unix time divided by the slot length), so they line up.

import { type ClusterNode, type Counts, type OpCounts, statsOf } from "./api";
import { now } from "./format";

const KEYS = ["requests", "client_errors", "server_errors", "bytes_in", "bytes_out", "latency_us"] as const;

const zero = (): Counts => ({
  requests: 0,
  client_errors: 0,
  server_errors: 0,
  bytes_in: 0,
  bytes_out: 0,
  latency_us: 0,
});

function add(acc: Counts, c: Counts) {
  for (const k of KEYS) acc[k] += c[k];
}

export interface History {
  slotSecs: number;
  slots: Map<number, Counts>;
}

export function mergeHistory(nodes: ClusterNode[]): History {
  const slots = new Map<number, Counts>();
  let slotSecs = 10;
  for (const n of nodes) {
    const r = statsOf(n)?.requests;
    if (!r) continue;
    slotSecs = r.slot_secs;
    for (const s of r.history) {
      const acc = slots.get(s.t) ?? zero();
      add(acc, s);
      slots.set(s.t, acc);
    }
  }
  return { slotSecs, slots };
}

export interface Rates {
  requests: number;
  client_errors: number;
  server_errors: number;
  bytes_in: number;
  bytes_out: number;
  /** Average seconds to the response head, or null without requests. */
  latency: number | null;
}

/** Per-second rates over the complete slots of the last `window` seconds. */
export function recentRates(h: History, window = 60): Rates {
  const t = now();
  const sum = zero();
  for (const [start, c] of h.slots) {
    const end = start + h.slotSecs;
    if (end <= t && end > t - window) add(sum, c);
  }
  return {
    requests: sum.requests / window,
    client_errors: sum.client_errors / window,
    server_errors: sum.server_errors / window,
    bytes_in: sum.bytes_in / window,
    bytes_out: sum.bytes_out / window,
    latency: sum.requests ? sum.latency_us / sum.requests / 1e6 : null,
  };
}

export type Point = [number, number];

/** One point per complete slot of the last `span` seconds; slots without
 * requests are zeroes. */
export function series(h: History, span: number, value: (c: Counts) => number): Point[] {
  const step = h.slotSecs;
  const last = Math.floor(now() / step) * step - step;
  const points: Point[] = [];
  for (let t = last - span + step; t <= last; t += step) {
    const c = h.slots.get(t);
    points.push([t, c ? value(c) : 0]);
  }
  return points;
}

/** Totals by operation, of the nodes that reported them. */
export function opsTotals(nodes: ClusterNode[]): OpCounts[] {
  const ops = new Map<string, OpCounts>();
  for (const n of nodes) {
    for (const o of statsOf(n)?.requests.ops ?? []) {
      const acc = ops.get(o.op) ?? { op: o.op, ...zero() };
      add(acc, o);
      ops.set(o.op, acc);
    }
  }
  return [...ops.values()];
}
