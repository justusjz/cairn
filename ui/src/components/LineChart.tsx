// A line chart over time, as SVG. It's drawn at the width it's laid out at
// (rather than scaled), so that its text keeps its shape.

import { For, Show, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { clock } from "../format";
import type { Point } from "../metrics";

export interface Series {
  name: string;
  /** Which of the `--series-N` colours. */
  color: 1 | 2 | 3 | 4;
  fill?: boolean;
  points: Point[];
}

const H = 190;
const LEFT = 56;
const RIGHT = 8;
const TOP = 8;
const BOTTOM = 22;

/** The smallest round number at least `v`, for the top of the scale. */
function niceMax(v: number): number {
  if (v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * exp) return m * exp;
  return 10 * exp;
}

export function LineChart(props: { series: Series[]; format: (v: number) => string }) {
  let svg!: SVGSVGElement;
  const [width, setWidth] = createSignal(0);
  const [hover, setHover] = createSignal<number | null>(null);
  onMount(() => {
    const observer = new ResizeObserver(() => setWidth(Math.round(svg.getBoundingClientRect().width)));
    observer.observe(svg);
    onCleanup(() => observer.disconnect());
  });

  const scale = createMemo(() => {
    const points = props.series[0]?.points ?? [];
    const t0 = points[0]?.[0] ?? 0;
    const t1 = points[points.length - 1]?.[0] ?? 1;
    const max = niceMax(Math.max(0, ...props.series.flatMap((s) => s.points.map((p) => p[1]))));
    const w = width();
    return {
      points,
      t0,
      t1,
      max,
      x: (t: number) => LEFT + ((t - t0) / Math.max(1, t1 - t0)) * (w - LEFT - RIGHT),
      y: (v: number) => TOP + (1 - v / max) * (H - TOP - BOTTOM),
    };
  });
  const path = (s: Series) => s.points.map((p, i) => (i ? "L" : "M") + scale().x(p[0]).toFixed(1) + "," + scale().y(p[1]).toFixed(1)).join("");
  const area = (s: Series) => {
    const { x, y, t0, t1 } = scale();
    return path(s) + `L${x(t1)},${y(0)}L${x(t0)},${y(0)}Z`;
  };
  const ticks = () => {
    const { t0, t1 } = scale();
    const n = Math.max(2, Math.min(6, Math.floor((width() - LEFT) / 70)));
    return Array.from({ length: n + 1 }, (_, i) => ({ t: t0 + ((t1 - t0) * i) / n, i, n }));
  };
  const onMove = (ev: MouseEvent) => {
    const { points } = scale();
    if (!points.length || !width()) return;
    const px = ev.clientX - svg.getBoundingClientRect().left;
    const idx = Math.round(((px - LEFT) / (width() - LEFT - RIGHT)) * (points.length - 1));
    setHover(Math.max(0, Math.min(points.length - 1, idx)));
  };

  return (
    <div class="chart">
      <svg ref={svg} viewBox={`0 0 ${width()} ${H}`} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <Show when={width() > 0}>
          <For each={[0, 1, 2, 3, 4]}>
            {(i) => {
              const v = () => (scale().max * i) / 4;
              return (
                <>
                  <line class="grid-line" x1={LEFT} x2={width() - RIGHT} y1={scale().y(v())} y2={scale().y(v())} />
                  <text class="axis-label" x={LEFT - 6} y={scale().y(v()) + 4} text-anchor="end">
                    {props.format(v())}
                  </text>
                </>
              );
            }}
          </For>
          <For each={ticks()}>
            {(tick) => (
              <text
                class="axis-label"
                x={scale().x(tick.t)}
                y={H - 6}
                text-anchor={tick.i === 0 ? "start" : tick.i === tick.n ? "end" : "middle"}
              >
                {clock(tick.t)}
              </text>
            )}
          </For>
          <For each={props.series}>
            {(s) => (
              <>
                <Show when={s.fill}>
                  <path class={`area c${s.color}`} d={area(s)} />
                </Show>
                <path class={`line c${s.color}`} d={path(s)} />
              </>
            )}
          </For>
          <Show when={hover() !== null}>
            <line
              class="cursor"
              x1={scale().x(scale().points[hover()!][0])}
              x2={scale().x(scale().points[hover()!][0])}
              y1={TOP}
              y2={H - BOTTOM}
            />
          </Show>
        </Show>
      </svg>
      <Show when={hover() !== null && scale().points[hover()!]}>
        <div
          class="tooltip"
          style={{ left: Math.max(0, Math.min(scale().x(scale().points[hover()!][0]) + 12, width() - 160)) + "px" }}
        >
          <div class="t">{clock(scale().points[hover()!][0], true)}</div>
          <For each={props.series}>
            {(s) => (
              <div>
                {s.name}: {props.format(s.points[hover()!]?.[1] ?? 0)}
              </div>
            )}
          </For>
        </div>
      </Show>
      <div class="legend">
        <For each={props.series}>
          {(s) => (
            <span>
              <i class={`c${s.color}`} />
              {s.name}
            </span>
          )}
        </For>
      </div>
    </div>
  );
}
