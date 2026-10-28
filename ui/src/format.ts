// How numbers, sizes and times are shown.

export function bytes(n: number | null | undefined): string {
  if (n == null) return "–";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  let v = n;
  while (Math.abs(v) >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return (i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + " " + units[i];
}

export function num(n: number | null | undefined): string {
  return n == null ? "–" : n.toLocaleString("en-US");
}

/** A per-second rate. */
export function rate(n: number): string {
  if (!isFinite(n)) return "–";
  if (n === 0) return "0";
  if (n < 0.1) return n.toFixed(3);
  if (n < 10) return n.toFixed(2);
  if (n < 1000) return n.toFixed(1);
  return num(Math.round(n));
}

export function pct(part: number, whole: number): string {
  if (!whole) return "–";
  const p = (100 * part) / whole;
  return (p > 0 && p < 0.1 ? "<0.1" : p.toFixed(p < 10 ? 1 : 0)) + "%";
}

export function duration(secs: number | null | undefined): string {
  if (secs == null || !isFinite(secs)) return "–";
  secs = Math.max(0, secs);
  if (secs < 1) return Math.round(secs * 1000) + " ms";
  if (secs < 60) return secs.toFixed(secs < 10 ? 1 : 0) + " s";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${Math.floor(secs % 60)}s`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}

export const now = () => Date.now() / 1000;

export function ago(t: number | null | undefined): string {
  return t ? duration(now() - t) + " ago" : "never";
}

const pad = (n: number) => String(n).padStart(2, "0");

export function date(t: number | null | undefined): string {
  if (!t) return "–";
  const d = new Date(t * 1000);
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

export function clock(t: number, seconds = false): string {
  const d = new Date(t * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}` + (seconds ? ":" + pad(d.getSeconds()) : "");
}

export function hex(n: number, digits = 4): string {
  return "0x" + n.toString(16).padStart(digits, "0");
}
