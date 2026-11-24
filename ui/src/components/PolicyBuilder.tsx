// A policy document's editor, as a visual builder or as its JSON: two views
// of the same text, which stays the truth. The builder shows each statement
// as a card (its effect, principals, actions, resources and conditions), and
// writes back only what's changed; a statement it can't show whole (a field
// it doesn't know, a value of an odd shape) is a card of its own JSON, so
// nothing is dropped or simplified away. What it knows of the language (each
// service's actions, the operators, the condition keys, and how Cairn treats
// each) comes from the server's policy catalog (`/api/policy-catalog`).
//
// For S3, it offers levels of access to a bucket (read, write, delete
// versions, manage), each a set of actions a statement has or hasn't, and
// says so of the statements whose actions are just such levels.
//
// It warns of the mistakes that make a policy quietly do nothing: an S3
// action about objects with only buckets as resources (and the other way
// round), a condition key none of the actions has, or one no request to
// Cairn ever carries.

import { For, Index, type JSX, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { type CatalogKey, type CatalogLevel, type PolicyCatalog, api } from "../api";
import { api as session } from "../session";

/** What a policy is attached to, which decides what it says: the principal
 * it names, the actions and resources it may. */
export type PolicyKind = "identity" | "scp" | "bucket" | "trust" | "topic" | "tables";

// ─── What the builder knows ──────────────────────────────────────────────────

const [catalog, setCatalog] = createSignal<PolicyCatalog>();
const [account, setAccount] = createSignal("");
let loading = false;

/** Loads the catalog (and the account's ID, for principals), once. */
function load() {
  if (loading) return;
  loading = true;
  api.policyCatalog().then(setCatalog, () => (loading = false));
  session.me().then((m) => setAccount(m.identity.account_id ?? ""), () => {});
}

type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any

/** A string or a list of them, as a list. */
const list = (v: Json): string[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const isStrings = (v: Json) => typeof v === "string" || (Array.isArray(v) && v.every((x) => typeof x === "string"));
const isObject = (v: Json): v is Record<string, Json> => typeof v === "object" && v !== null && !Array.isArray(v);
const pretty = (v: Json) => JSON.stringify(v, null, 2);

/** A wildcard pattern (`*`, `?`) as a regular expression, regardless of case. */
function pattern(text: string): RegExp {
  const escaped = text.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

/** The catalog's actions `action` (with wildcards, perhaps) names, or `null`
 * if it's of a service the catalog doesn't know. */
function expand(action: string): { name: string; resource?: string | null; keys: string[] }[] | null {
  const c = catalog();
  if (!c) return null;
  if (action === "*") return c.services.flatMap((s) => s.actions.map((a) => ({ ...a, name: `${s.prefix}:${a.name}` })));
  const [prefix, name] = action.split(/:(.*)/s);
  const service = c.services.find((s) => s.prefix.toLowerCase() === prefix.toLowerCase());
  if (!service || name === undefined) return null;
  const re = pattern(name);
  return service.actions.filter((a) => re.test(a.name)).map((a) => ({ ...a, name: `${service.prefix}:${a.name}` }));
}

/** The services whose actions a policy of `kind` may name. */
function services(kind: PolicyKind, bucket?: string): string[] {
  switch (kind) {
    case "bucket":
      return [bucket?.endsWith("--x-s3") ? "s3express" : "s3"];
    case "trust":
      return ["sts"];
    case "topic":
      return ["sns"];
    case "tables":
      return ["s3tables"];
    default:
      return ["s3", "s3express", "s3tables", "sns", "kms", "sts"];
  }
}

/** The actions to suggest for a policy of `kind`. */
function suggestedActions(kind: PolicyKind, bucket?: string): string[] {
  const c = catalog();
  if (!c) return [];
  const out: string[] = kind === "identity" || kind === "scp" ? ["*"] : [];
  for (const s of c.services) {
    if (!services(kind, bucket).includes(s.prefix)) continue;
    if (kind !== "trust") out.push(`${s.prefix}:*`);
    for (const a of s.actions) {
      // A bucket policy's: about the bucket or its objects, but not making it.
      if (kind === "bucket" && s.prefix === "s3" && (!["bucket", "object"].includes(a.resource ?? "") || a.name === "CreateBucket")) continue;
      out.push(`${s.prefix}:${a.name}`);
    }
  }
  return out;
}

/** The condition keys to suggest for a policy of `kind`. */
function suggestedKeys(kind: PolicyKind): CatalogKey[] {
  const c = catalog();
  if (!c) return [];
  return c.keys.filter((k) => {
    const prefix = k.name.split(":")[0];
    if (prefix === "aws") return true;
    if (prefix === "s3") return ["identity", "scp", "bucket"].includes(kind);
    if (prefix === "sts") return kind === "trust";
    return false;
  });
}

/** A key's entry in the catalog (a trailing `/` takes any tag key). */
function catalogKey(key: string): CatalogKey | undefined {
  const lower = key.toLowerCase();
  return catalog()?.keys.find((k) => {
    const name = k.name.toLowerCase();
    return name.endsWith("/") ? lower.startsWith(name) && lower.length > name.length : lower === name;
  });
}

/** Whether one of an action's keys (as the catalog writes them) is `key`. */
function takesKey(keys: string[], key: string): boolean {
  const lower = key.toLowerCase();
  return keys.some((k) => {
    const name = k.toLowerCase();
    return name.endsWith("/") ? lower.startsWith(name) && lower.length > name.length : lower === name;
  });
}

/** Whether `actions` (patterns, perhaps) name `action`. */
const names = (actions: string[], action: string) => actions.some((a) => pattern(a).test(action));
/** Whether `actions` have `action` itself (not by a wildcard). */
const has = (actions: string[], action: string) => actions.some((a) => a.toLowerCase() === action.toLowerCase());

/** A level of access in a statement's actions: all of its own (`on`), all
 * only by wildcards (`wildcard`), some (`some`) or none (`off`). */
function levelState(actions: string[], level: CatalogLevel): "on" | "wildcard" | "some" | "off" {
  if (level.actions.every((a) => has(actions, a))) return "on";
  if (level.actions.every((a) => names(actions, a))) return "wildcard";
  return level.actions.some((a) => names(actions, a)) ? "some" : "off";
}

/** The levels `actions` are exactly, or `null` if they're anything else. */
function exactLevels(actions: string[]): CatalogLevel[] | null {
  const levels = (catalog()?.levels ?? []).filter((l) => levelState(actions, l) === "on");
  if (!levels.length || !actions.every((a) => levels.some((l) => has(l.actions, a)))) return null;
  return levels;
}

// ─── Statements ──────────────────────────────────────────────────────────────

const FIELDS = ["Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition"];

/** An operator's parts: `[ForAllValues:|ForAnyValue:]Name[IfExists]`. */
type Operator = { set: "" | "ForAllValues:" | "ForAnyValue:"; base: string; ifExists: boolean };

function operator(name: string): Operator | null {
  const m = name.match(/^(ForAllValues:|ForAnyValue:)?([A-Za-z]+?)(IfExists)?$/);
  if (!m) return null;
  const known = catalog()?.operators;
  if (known && !known.includes(m[2])) return null;
  if (m[2] === "Null" && m[3]) return null;
  return { set: (m[1] ?? "") as Operator["set"], base: m[2], ifExists: !!m[3] };
}

const operatorName = (o: Operator) => `${o.set}${o.base}${o.ifExists && o.base !== "Null" ? "IfExists" : ""}`;

/** Why the builder can't show a statement whole, or `null` if it can. */
function unshowable(s: Json): string | null {
  if (!isObject(s)) return "It isn't an object.";
  const unknown = Object.keys(s).find((k) => !FIELDS.includes(k));
  if (unknown) return `It has ${unknown}, which the builder doesn't show.`;
  if (s.Sid !== undefined && typeof s.Sid !== "string") return "Its Sid isn't a string.";
  if (s.Effect !== "Allow" && s.Effect !== "Deny") return "Its Effect isn't Allow or Deny.";
  for (const [a, b] of [["Action", "NotAction"], ["Resource", "NotResource"], ["Principal", "NotPrincipal"]]) {
    if (s[a] !== undefined && s[b] !== undefined) return `It has both ${a} and ${b}.`;
  }
  for (const f of ["Action", "NotAction", "Resource", "NotResource"]) {
    if (s[f] !== undefined && !isStrings(s[f])) return `Its ${f} isn't a string or a list of them.`;
  }
  for (const f of ["Principal", "NotPrincipal"]) {
    const p = s[f];
    if (p === undefined || p === "*") continue;
    if (!isObject(p) || !Object.values(p).every(isStrings)) return `Its ${f} isn't "*" or an object of lists.`;
  }
  if (s.Condition !== undefined) {
    if (!isObject(s.Condition)) return "Its Condition isn't an object.";
    for (const [op, keys] of Object.entries(s.Condition)) {
      if (!operator(op)) return `It has an operator the builder doesn't know: ${op}.`;
      if (!isObject(keys)) return `Its ${op} isn't an object.`;
      const scalar = (v: Json) => ["string", "number", "boolean"].includes(typeof v);
      for (const v of Object.values(keys)) {
        if (!(scalar(v) || (Array.isArray(v) && v.every(scalar)))) return `A value of its ${op} isn't a string or a list of them.`;
      }
    }
  }
  return null;
}

/** `s` with `field` set to `value` (or removed, if `undefined`), keeping the
 * fields' order; `instead` is a field `field` replaces (Action for
 * NotAction, say), whose place it takes. */
function withField(s: Json, field: string, value: Json, instead?: string): Json {
  const out: Json = {};
  let placed = false;
  for (const [k, v] of Object.entries(s)) {
    if (k === field || k === instead) {
      if (!placed && value !== undefined) out[field] = value;
      placed = true;
    } else {
      out[k] = v;
    }
  }
  if (!placed && value !== undefined) out[field] = value;
  return out;
}

/** A list as a policy writes it: one value alone, unless it was a list. */
const written = (values: string[], before: Json): Json => (values.length === 1 && !Array.isArray(before) ? values[0] : values);

type Row = { op: string; key: string; value: Json };

function conditionRows(condition: Json): Row[] {
  if (!isObject(condition)) return [];
  return Object.entries(condition).flatMap(([op, keys]) =>
    Object.entries(keys as Record<string, Json>).map(([key, value]) => ({ op, key, value })),
  );
}

function conditionOf(rows: Row[]): Json {
  if (!rows.length) return undefined;
  const out: Record<string, Record<string, Json>> = {};
  for (const r of rows) (out[r.op] ??= {})[r.key] = r.value;
  return out;
}

/** S3's resources as a line says them: a bucket and its objects (both
 * named) as `bucket and its objects`. */
function resourceNames(resources: string[]): string[] {
  const out: string[] = [];
  for (const r of resources) {
    const bucket = r.match(/^arn:aws:s3:::([^/]+)$/)?.[1];
    if (bucket && resources.includes(`${r}/*`)) out.push(`${bucket} and its objects`);
    else if (!(r.endsWith("/*") && resources.includes(r.slice(0, -2)) && /^arn:aws:s3:::[^/]+\/\*$/.test(r))) out.push(r);
  }
  return out;
}

/** The statement, in a line. */
function describe(s: Json, kind: PolicyKind): string {
  const some = (values: string[], none: string) =>
    values.length === 0 ? none : values.length <= 2 ? values.join(", ") : `${values.slice(0, 2).join(", ")} and ${values.length - 2} more`;
  const levels = s.NotAction === undefined ? exactLevels(list(s.Action)) : null;
  const actions =
    s.NotAction !== undefined
      ? `everything but ${some(list(s.NotAction), "nothing")}`
      : levels
        ? `${levels.map((l) => l.label.toLowerCase()).join(", ")} access`
        : some(list(s.Action), "no actions");
  const resources = s.NotResource !== undefined ? `everything but ${some(list(s.NotResource), "nothing")}` : some(resourceNames(list(s.Resource)), "nothing");
  const principal = s.Principal ?? s.NotPrincipal;
  let who = "";
  if (principal !== undefined) {
    const named = principal === "*" ? ["anyone"] : Object.values(principal).flatMap(list);
    who = ` for ${s.NotPrincipal !== undefined ? "all but " : ""}${some(named.map((p) => (p === "*" ? "anyone" : p)), "no one")}`;
  }
  const conditions = conditionRows(s.Condition).length;
  const on = kind === "trust" && s.Resource === undefined ? "" : ` on ${resources}`;
  return `${s.Effect} ${actions}${on}${who}${conditions ? `, if ${conditions === 1 ? "a condition holds" : `${conditions} conditions hold`}` : ""}`;
}

// ─── Warnings ────────────────────────────────────────────────────────────────

type Warning = { tone: "warn" | "bad"; text: JSX.Element; fix?: { label: string; apply: () => void } };

/** What an S3 resource names: a bucket, an object, either (a wildcard in a
 * bucket's name), anything (`*`), or not S3's. */
function s3Resource(r: string): "bucket" | "object" | "either" | "any" | "other" {
  if (r === "*") return "any";
  const m = r.match(/^arn:aws:s3:::(.*)$/);
  if (!m) return "other";
  if (m[1].includes("/")) return "object";
  return /[*?]/.test(m[1]) ? "either" : "bucket";
}

function warnings(s: Json, kind: PolicyKind, set: (s: Json) => void): Warning[] {
  const out: Warning[] = [];
  const actions = list(s.Action);
  const resources = list(s.Resource);
  if (s.Action !== undefined && !actions.length) out.push({ tone: "bad", text: "No actions: name at least one." });
  if (kind !== "trust" && s.Resource !== undefined && !resources.length) out.push({ tone: "bad", text: "No resources: name at least one." });
  if (kind !== "trust" && s.Resource === undefined && s.NotResource === undefined) out.push({ tone: "bad", text: "No Resource: every statement needs one." });
  if (["bucket", "trust", "topic", "tables"].includes(kind) && s.Principal === undefined && s.NotPrincipal === undefined) {
    out.push({ tone: "bad", text: "No Principal: this kind of policy names who each statement is about." });
  }
  if (kind === "bucket" && s.Effect === "Allow" && s.Principal !== undefined && !s.Condition) {
    const p = s.Principal;
    if (p === "*" || list(isObject(p) ? p.AWS : undefined).includes("*")) {
      out.push({ tone: "warn", text: "Anyone may do this, unsigned requests too: the bucket is public (unless its public access block stops it)." });
    }
  }
  // Actions about objects with only buckets as resources (or the other way
  // round): each named exactly, since a wildcard names both kinds.
  if (s.Action !== undefined && s.Resource !== undefined && catalog()) {
    const kinds = resources.map(s3Resource);
    const s3 = kinds.some((k) => k !== "other");
    const exact = actions.filter((a) => /^s3:[^*?]+$/i.test(a)).flatMap((a) => expand(a) ?? []);
    const about = (r: string) => exact.filter((a) => a.resource === r).map((a) => a.name);
    const has = (...k: string[]) => kinds.some((x) => k.includes(x));
    const objects = about("object");
    if (s3 && objects.length && !has("object", "either", "any")) {
      const buckets = resources.filter((r) => s3Resource(r) === "bucket");
      out.push({
        tone: "bad",
        text: (
          <>
            <span class="mono">{objects.join(", ")}</span> {objects.length === 1 ? "is" : "are"} about objects, but no
            resource names any: they'd be allowed on nothing. Objects are{" "}
            <span class="mono">arn:aws:s3:::bucket/*</span> (or <span class="mono">bucket/prefix/*</span>).
          </>
        ),
        fix: buckets.length
          ? { label: `Add ${buckets.map((b) => `${b}/*`).join(", ")}`, apply: () => set(withField(s, "Resource", [...resources, ...buckets.map((b) => `${b}/*`)])) }
          : undefined,
      });
    }
    const bucketActions = about("bucket");
    if (s3 && bucketActions.length && !has("bucket", "either", "any")) {
      const buckets = [...new Set(resources.filter((r) => s3Resource(r) === "object").map((r) => r.slice(0, r.indexOf("/"))))];
      out.push({
        tone: "bad",
        text: (
          <>
            <span class="mono">{bucketActions.join(", ")}</span> {bucketActions.length === 1 ? "is" : "are"} about the
            bucket itself, but every resource names objects: they'd be allowed on nothing. A bucket is{" "}
            <span class="mono">arn:aws:s3:::bucket</span>, without <span class="mono">/*</span>
            {bucketActions.some((a) => /ListBucket/i.test(a)) ? (
              <>
                ; to list only a prefix, add a condition on <span class="mono">s3:prefix</span>
              </>
            ) : null}
            .
          </>
        ),
        fix: buckets.length ? { label: `Add ${buckets.join(", ")}`, apply: () => set(withField(s, "Resource", [...resources, ...buckets])) } : undefined,
      });
    }
    const accountActions = about("account");
    if (s3 && accountActions.length && !has("any")) {
      out.push({
        tone: "bad",
        text: (
          <>
            <span class="mono">{accountActions.join(", ")}</span> {accountActions.length === 1 ? "is" : "are"} about no
            bucket or object: only the resource <span class="mono">*</span> allows {accountActions.length === 1 ? "it" : "them"}.
          </>
        ),
        fix: { label: "Add *", apply: () => set(withField(s, "Resource", [...resources, "*"])) },
      });
    }
  }
  // Condition keys: those Cairn's requests never carry, those it doesn't
  // decide yet, and S3's that none of the statement's actions has.
  const exactS3 = s.Action !== undefined && actions.length > 0 && actions.every((a) => /^s3:[^*?]+$/i.test(a));
  const s3Actions = exactS3 ? actions.flatMap((a) => expand(a) ?? []) : [];
  for (const row of conditionRows(s.Condition)) {
    if (!row.key) continue;
    const known = catalogKey(row.key);
    const key = <span class="mono">{row.key}</span>;
    if (known?.support === "absent") {
      out.push({ tone: "warn", text: <>No request to Cairn ever has {key}: a condition on it holds only as a missing key's does.</> });
    } else if (known?.support === "unsupported") {
      out.push({ tone: "bad", text: <>Cairn doesn't decide {key} yet, so it refuses policies that name it.</> });
    }
    if (row.key.toLowerCase().startsWith("s3:") && s3Actions.length === actions.length && s3Actions.length && !s3Actions.some((a) => takesKey(a.keys, row.key))) {
      out.push({
        tone: "warn",
        text: (
          <>
            None of the statement's actions has {key}, so it's always missing: the condition holds only as a missing key's does
            (never, unless it's negated or <span class="mono">IfExists</span>).
          </>
        ),
      });
    }
  }
  return out;
}

// ─── Pieces ──────────────────────────────────────────────────────────────────

let ids = 0;

/** Values as chips, and an input that adds one (or several, split by
 * `split`); with suggestions, if there are. */
function Chips(props: {
  values: string[];
  set: (values: string[]) => void;
  label: string;
  placeholder: string;
  suggestions?: string[];
  split?: RegExp;
  chip?: (value: string) => { title?: string; bad?: boolean; label?: string };
}) {
  const id = `policy-list-${++ids}`;
  const [text, setText] = createSignal("");
  const add = () => {
    const added = (props.split ? text().split(props.split) : [text()]).map((v) => v.trim()).filter((v) => v);
    if (!added.length) return;
    props.set([...props.values, ...added.filter((v) => !props.values.includes(v))]);
    setText("");
  };
  return (
    <div class="chips">
      <Index each={props.values}>
        {(v, i) => {
          const look = () => props.chip?.(v()) ?? {};
          return (
            <span class="chip mono" classList={{ deny: !!look().bad }} title={look().title}>
              {look().label ?? v()}
              <button type="button" aria-label={`Remove ${v()}`} onClick={() => props.set(props.values.filter((_, j) => j !== i))}>
                ×
              </button>
            </span>
          );
        }}
      </Index>
      <input
        type="text"
        class="mono"
        aria-label={props.label}
        placeholder={props.placeholder}
        list={props.suggestions?.length ? id : undefined}
        value={text()}
        onInput={(e) => setText(e.currentTarget.value)}
        onChange={add}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            add();
          }
        }}
      />
      <Show when={props.suggestions?.length}>
        <datalist id={id}>
          <For each={props.suggestions}>{(s) => <option value={s} />}</For>
        </datalist>
      </Show>
    </div>
  );
}

/** A `Not...` toggle's select: `field`, or everything but it. */
function NotSelect(props: { not: boolean; set: (not: boolean) => void; label: string; yes: string; no: string }) {
  return (
    <select class="label" aria-label={props.label} value={props.not ? "not" : ""} onChange={(e) => props.set(e.currentTarget.value === "not")}>
      <option value="">{props.yes}</option>
      <option value="not">{props.no}</option>
    </select>
  );
}

function actionChip(action: string): { title?: string; bad?: boolean } {
  const named = expand(action);
  if (named === null) return { title: catalog() ? "A service Cairn's catalog doesn't list: taken as written" : undefined };
  if (!named.length) return { bad: true, title: "No such action" };
  if (/[*?]/.test(action)) {
    const shown = named.slice(0, 12).map((a) => a.name).join("\n");
    return { title: `${named.length} action${named.length === 1 ? "" : "s"}:\n${shown}${named.length > 12 ? "\n…" : ""}` };
  }
  const resource = named[0].resource;
  return { title: resource ? `About ${resource === "account" ? "no resource (*)" : resource === "other" ? "something Cairn doesn't have" : `a ${resource}`}` : undefined };
}

/** The principal kinds to show for a policy of `kind`, besides those a
 * statement has. */
function principalKinds(kind: PolicyKind): string[] {
  switch (kind) {
    case "trust":
      return ["AWS", "Federated"];
    case "topic":
    case "bucket":
      return ["AWS", "Service"];
    default:
      return ["AWS"];
  }
}

function PrincipalEditor(props: { statement: Json; kind: PolicyKind; set: (s: Json) => void }) {
  const field = () => (props.statement.NotPrincipal !== undefined ? "NotPrincipal" : "Principal");
  const value = () => props.statement[field()];
  const anyone = () => value() === "*";
  const kinds = () => [...new Set([...principalKinds(props.kind), ...(isObject(value()) ? Object.keys(value()) : [])])];
  const setValue = (v: Json) => props.set(withField(props.statement, field(), v));
  const setKind = (k: string, values: string[]) => {
    const before = isObject(value()) ? value() : {};
    const next = withField(before, k, values.length ? written(values, before[k]) : undefined);
    setValue(next);
  };
  const suggestions = (k: string) => {
    const a = account();
    if (k === "AWS") return a ? [`arn:aws:iam::${a}:root`, `arn:aws:iam::${a}:user/`, `arn:aws:iam::${a}:role/`, "*"] : ["*"];
    if (k === "Service") return ["s3.amazonaws.com"];
    if (k === "Federated" && a) return [`arn:aws:iam::${a}:oidc-provider/`];
    return [];
  };
  const placeholder = (k: string) =>
    k === "AWS"
      ? "account ID, or arn:aws:iam::ACCOUNT:user/NAME (or role/NAME)"
      : k === "Federated"
        ? "arn:aws:iam::ACCOUNT:oidc-provider/HOST"
        : k === "Service"
          ? "s3.amazonaws.com"
          : "principal";
  return (
    <>
      <div class="form-row">
        <NotSelect
          label="Principal or everyone but"
          not={field() === "NotPrincipal"}
          set={(not) => props.set(withField(props.statement, not ? "NotPrincipal" : "Principal", value(), not ? "Principal" : "NotPrincipal"))}
          yes="Who"
          no="Everyone but"
        />
        <label class="check">
          <input type="checkbox" checked={anyone()} onChange={(e) => setValue(e.currentTarget.checked ? "*" : { AWS: [] })} />
          Anyone (<span class="mono">*</span>, unsigned requests too)
        </label>
      </div>
      <Show when={!anyone()}>
        <For each={kinds()}>
          {(k) => (
            <div class="form-row">
              <span class="label mono">{k}</span>
              <Chips
                values={list(isObject(value()) ? value()[k] : undefined)}
                set={(values) => setKind(k, values)}
                label={`${k} principals`}
                placeholder={placeholder(k)}
                suggestions={suggestions(k)}
                split={/[\s,]+/}
              />
            </div>
          )}
        </For>
      </Show>
    </>
  );
}

/** Toggles levels of access to a bucket: each adds its actions, or takes
 * away those no other level that's on has. */
function LevelPicker(props: { actions: string[]; set: (actions: string[]) => void }) {
  const levels = () => catalog()?.levels ?? [];
  const toggle = (level: CatalogLevel) => {
    const actions = props.actions;
    if (levelState(actions, level) === "on") {
      const kept = levels().filter((l) => l !== level && levelState(actions, l) === "on");
      props.set(actions.filter((a) => !has(level.actions, a) || kept.some((l) => has(l.actions, a))));
    } else {
      props.set([...actions, ...level.actions.filter((a) => !names(actions, a))]);
    }
  };
  return (
    <div class="form-row">
      <span class="label">Access</span>
      <For each={levels()}>
        {(l) => {
          const state = () => levelState(props.actions, l);
          return (
            <button
              type="button"
              class="small"
              classList={{ active: state() === "on" || state() === "wildcard", partial: state() === "some" }}
              aria-pressed={state() === "on" || state() === "wildcard"}
              disabled={state() === "wildcard"}
              title={
                state() === "wildcard"
                  ? "A wildcard among the actions has it already"
                  : state() === "some"
                    ? `Some of its ${l.actions.length} actions: add the rest`
                    : `${l.actions.length} actions: ${l.actions.join(", ")}`
              }
              onClick={() => toggle(l)}
            >
              {l.label}
            </button>
          );
        }}
      </For>
      <span class="subtle small">on a bucket and its objects: add them below</span>
    </div>
  );
}

/** Adds a bucket's ARN and its objects', its objects', a prefix's, or the
 * bucket's. */
function ResourceHelper(props: { buckets: string[]; bucket?: string; add: (arns: string[]) => void }) {
  const [bucket, setBucket] = createSignal(props.bucket ?? props.buckets[0] ?? "");
  const [what, setWhat] = createSignal<"both" | "bucket" | "objects" | "prefix">("both");
  const [prefix, setPrefix] = createSignal("");
  const id = `policy-buckets-${++ids}`;
  const arns = () => {
    const b = bucket().trim();
    const p = prefix().trim().replace(/^\/+/, "").replace(/\*$/, "");
    switch (what()) {
      case "both":
        return [`arn:aws:s3:::${b}`, `arn:aws:s3:::${b}/*`];
      case "bucket":
        return [`arn:aws:s3:::${b}`];
      case "objects":
        return [`arn:aws:s3:::${b}/*`];
      case "prefix":
        return [`arn:aws:s3:::${b}/${p}*`];
    }
  };
  return (
    <div class="form-row">
      <span class="label" />
      <span class="subtle small">Add</span>
      <select aria-label="What" value={what()} onChange={(e) => setWhat(e.currentTarget.value as "bucket")}>
        <option value="both">the bucket and the objects of</option>
        <option value="objects">the objects of</option>
        <option value="prefix">the objects under a prefix of</option>
        <option value="bucket">the bucket</option>
      </select>
      <Show
        when={!props.bucket}
        fallback={<span class="mono">{props.bucket}</span>}
      >
        <input type="text" class="narrow" aria-label="Bucket" placeholder="bucket, or team-*" list={id} value={bucket()} onInput={(e) => setBucket(e.currentTarget.value)} />
        <datalist id={id}>
          <For each={props.buckets}>{(b) => <option value={b} />}</For>
        </datalist>
      </Show>
      <Show when={what() === "prefix"}>
        <input type="text" class="narrow mono" aria-label="Prefix" placeholder="logs/" value={prefix()} onInput={(e) => setPrefix(e.currentTarget.value)} />
      </Show>
      <button type="button" class="small" disabled={!bucket().trim() || (what() === "prefix" && !prefix().trim())} onClick={() => props.add(arns())}>
        Add <span class="mono">{arns().join(", ")}</span>
      </button>
    </div>
  );
}

const PLACEHOLDERS: [RegExp, string][] = [
  [/IpAddress/, "10.0.0.0/8"],
  [/^Bool/, "true"],
  [/^Null/, "true: missing; false: present"],
  [/^Date/, "2026-01-01T00:00:00Z"],
  [/^Numeric/, "number"],
  [/^Arn/, "arn:aws:…"],
];

function ConditionRow(props: { row: Row; keysId: string; set: (row: Row) => void; remove: () => void }) {
  const op = () => operator(props.row.op) ?? { set: "" as const, base: props.row.op, ifExists: false };
  const setOp = (change: Partial<Operator>) => props.set({ ...props.row, op: operatorName({ ...op(), ...change }) });
  const operators = () => {
    const known = catalog()?.operators ?? [];
    return known.includes(op().base) ? known : [op().base, ...known];
  };
  const support = () => catalogKey(props.row.key)?.support;
  return (
    <div class="condition">
      <div class="form-row">
        <input
          type="text"
          class="mono narrow"
          aria-label="Condition key"
          placeholder="aws:SourceIp"
          list={props.keysId}
          value={props.row.key}
          classList={{ "bad-input": support() === "unsupported" }}
          onInput={(e) => props.set({ ...props.row, key: e.currentTarget.value })}
        />
        <select aria-label="For values" value={op().set} onChange={(e) => setOp({ set: e.currentTarget.value as Operator["set"] })}>
          <option value="">its value</option>
          <option value="ForAnyValue:">any of its values</option>
          <option value="ForAllValues:">all of its values</option>
        </select>
        <select aria-label="Operator" value={op().base} onChange={(e) => setOp({ base: e.currentTarget.value })}>
          <For each={operators()}>{(o) => <option value={o}>{o}</option>}</For>
        </select>
      </div>
      <div class="form-row">
        <Chips
          values={list(props.row.value).map(String)}
          set={(values) => props.set({ ...props.row, value: written(values, props.row.value) })}
          label="Values"
          placeholder={PLACEHOLDERS.find(([re]) => re.test(op().base))?.[1] ?? "value"}
        />
        <label class="check" title="The condition holds too if the request doesn't have the key">
          <input type="checkbox" disabled={op().base === "Null"} checked={op().ifExists} onChange={(e) => setOp({ ifExists: e.currentTarget.checked })} />
          or missing
        </label>
        <button type="button" class="small" onClick={props.remove}>
          Remove
        </button>
      </div>
    </div>
  );
}

// ─── A statement ─────────────────────────────────────────────────────────────

function StatementCard(props: {
  statement: Json;
  n: number;
  kind: PolicyKind;
  buckets: string[];
  bucket?: string;
  set: (s: Json) => void;
  remove: () => void;
}) {
  const [asJson, setAsJson] = createSignal(false);
  const reason = () => unshowable(props.statement);
  const raw = () => asJson() || reason() !== null;
  const keysId = `policy-keys-${++ids}`;
  const s = () => props.statement;
  const field = (base: string) => (s()[`Not${base}`] !== undefined ? `Not${base}` : base);
  const setList = (base: string, values: string[]) => props.set(withField(s(), field(base), written(values, s()[field(base)])));
  const toggleNot = (base: string, not: boolean) =>
    props.set(withField(s(), not ? `Not${base}` : base, s()[field(base)] ?? [], not ? base : `Not${base}`));
  const rows = () => conditionRows(s().Condition);
  const setRows = (r: Row[]) => props.set(withField(s(), "Condition", conditionOf(r)));
  const shownWarnings = createMemo(() => (raw() ? [] : warnings(s(), props.kind, props.set)));
  const hasPrincipal = () => ["bucket", "trust", "topic", "tables"].includes(props.kind) || s().Principal !== undefined || s().NotPrincipal !== undefined;
  const hasResource = () => props.kind !== "trust" || s().Resource !== undefined || s().NotResource !== undefined;
  const s3Resources = () => ["identity", "scp", "bucket"].includes(props.kind) && !props.bucket?.endsWith("--x-s3");
  return (
    <section class="statement" classList={{ deny: !raw() && s().Effect === "Deny" }}>
      <header>
        <strong>Statement {props.n}</strong>
        <Show when={!raw()}>
          <span class="subtle small">{describe(s(), props.kind)}</span>
        </Show>
        <span class="spacer" />
        <button type="button" class="small" disabled={reason() !== null} title={reason() ?? undefined} onClick={() => setAsJson(!asJson())}>
          {raw() ? "Edit visually" : "Edit as JSON"}
        </button>
        <button type="button" class="small danger" onClick={props.remove}>
          Remove
        </button>
      </header>
      <Show when={!raw()} fallback={<RawStatement statement={s()} reason={reason()} set={props.set} />}>
        <div class="rule">
          <div class="form-row">
            <span class="label">Effect</span>
            <select aria-label="Effect" value={s().Effect} onChange={(e) => props.set(withField(s(), "Effect", e.currentTarget.value))}>
              <option value="Allow">Allow</option>
              <option value="Deny">Deny</option>
            </select>
            <input
              type="text"
              class="narrow"
              aria-label="Statement ID"
              placeholder="Sid (optional, letters and digits)"
              value={s().Sid ?? ""}
              onInput={(e) => props.set(withField(s(), "Sid", e.currentTarget.value || undefined))}
            />
          </div>
          <Show when={hasPrincipal()}>
            <PrincipalEditor statement={s()} kind={props.kind} set={props.set} />
          </Show>
          <div class="form-row">
            <NotSelect label="Actions or all but" not={field("Action") === "NotAction"} set={(not) => toggleNot("Action", not)} yes="Actions" no="All actions but" />
            <Chips
              values={list(s()[field("Action")])}
              set={(v) => setList("Action", v)}
              label="Actions"
              placeholder={props.kind === "trust" ? "sts:AssumeRole" : "s3:GetObject, or s3:Get*"}
              suggestions={suggestedActions(props.kind, props.bucket)}
              split={/[\s,]+/}
              chip={actionChip}
            />
          </div>
          <Show when={s3Resources() && field("Action") === "Action" && catalog()?.levels.length}>
            <LevelPicker actions={list(s().Action)} set={(v) => setList("Action", v)} />
          </Show>
          <Show when={hasResource()}>
            <div class="form-row">
              <NotSelect label="Resources or all but" not={field("Resource") === "NotResource"} set={(not) => toggleNot("Resource", not)} yes="Resources" no="All resources but" />
              <Chips
                values={list(s()[field("Resource")])}
                set={(v) => setList("Resource", v)}
                label="Resources"
                placeholder={s3Resources() ? "arn:aws:s3:::bucket/prefix/*, or *" : "an ARN, or *"}
                split={/[\s,]+/}
              />
            </div>
            <Show when={s3Resources()}>
              <ResourceHelper buckets={props.buckets} bucket={props.bucket} add={(arns) => setList("Resource", [...list(s()[field("Resource")]).filter((r) => !arns.includes(r)), ...arns])} />
            </Show>
          </Show>
          <div class="form-row">
            <span class="label">Conditions</span>
            <Show when={!rows().length}>
              <span class="subtle small">none: the statement applies to every request it names</span>
            </Show>
            <button
              type="button"
              class="small"
              onClick={() => {
                // One blank row at a time: two would be one key.
                if (rows().some((x) => x.op === "StringEquals" && !x.key)) return;
                setRows([...rows(), { op: "StringEquals", key: "", value: [] }]);
              }}
            >
              Add condition
            </button>
          </div>
          <Index each={rows()}>
            {(row, i) => (
              <ConditionRow
                row={row()}
                keysId={keysId}
                set={(changed) => setRows(rows().map((r, j) => (j === i ? changed : r)))}
                remove={() => setRows(rows().filter((_, j) => j !== i))}
              />
            )}
          </Index>
          <datalist id={keysId}>
            <For each={suggestedKeys(props.kind)}>{(k) => <option value={k.name}>{k.support === "evaluated" ? "" : k.support === "absent" ? "never present in Cairn" : "not decided by Cairn yet"}</option>}</For>
          </datalist>
          <Show when={shownWarnings().length}>
            <ul class="policy-warnings">
              <For each={shownWarnings()}>
                {(w) => (
                  <li class={w.tone === "bad" ? "error-text" : "warn-note"}>
                    {w.text}
                    <Show when={w.fix}>
                      {(f) => (
                        <>
                          {" "}
                          <button type="button" class="small" onClick={() => f().apply()}>
                            {f().label}
                          </button>
                        </>
                      )}
                    </Show>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </div>
      </Show>
    </section>
  );
}

/** A statement as its JSON: applied as soon as it parses. */
function RawStatement(props: { statement: Json; reason: string | null; set: (s: Json) => void }) {
  const [text, setText] = createSignal(pretty(props.statement));
  const [error, setError] = createSignal<string>();
  // The statement changed elsewhere (in the JSON view, say): show it, unless
  // it's what's typed here.
  createEffect(
    on(
      () => props.statement,
      (s) => {
        try {
          if (JSON.stringify(JSON.parse(text())) === JSON.stringify(s)) return;
        } catch {
          // Typed, and not JSON yet: it's what's shown.
          return;
        }
        setText(pretty(s));
      },
      { defer: true },
    ),
  );
  return (
    <>
      <Show when={props.reason}>
        <p class="subtle small">{props.reason} Edit its JSON here; nothing of it is lost.</p>
      </Show>
      <textarea
        class="policy statement-json"
        aria-label="Statement JSON"
        spellcheck={false}
        value={text()}
        onInput={(e) => {
          setText(e.currentTarget.value);
          try {
            props.set(JSON.parse(e.currentTarget.value));
            setError(undefined);
          } catch (err) {
            setError(`Not JSON yet, so not applied: ${(err as Error).message}`);
          }
        }}
      />
      <Show when={error()}>{(e) => <p class="error-text small">{e()}</p>}</Show>
    </>
  );
}

// ─── The document ────────────────────────────────────────────────────────────

/** A new statement for a policy of `kind`. */
function newStatement(kind: PolicyKind, bucket?: string, resource?: string): Json {
  switch (kind) {
    case "identity":
    case "scp":
      return { Effect: "Allow", Action: [], Resource: [] };
    case "bucket":
      return { Effect: "Allow", Principal: { AWS: [] }, Action: [], Resource: bucket ? [`arn:aws:s3:::${bucket}/*`] : [] };
    case "trust":
      return { Effect: "Allow", Principal: { AWS: [] }, Action: "sts:AssumeRole" };
    case "topic":
      return { Effect: "Allow", Principal: { AWS: [] }, Action: ["sns:Publish"], Resource: resource ?? "*" };
    case "tables":
      return { Effect: "Allow", Principal: { AWS: [] }, Action: [], Resource: resource ? [resource] : [] };
  }
}

const MODE_KEY = "cairn.policy-editor";

/** A policy document's editor: the visual builder, or its JSON. */
export function PolicyDocumentEditor(props: {
  kind: PolicyKind;
  document: string;
  setDocument: (d: string) => void;
  /** The JSON's label. */
  label: string;
  readOnly?: boolean;
  disabled?: boolean;
  /** Buckets to suggest as resources. */
  buckets?: string[];
  /** A bucket policy's bucket. */
  bucket?: string;
  /** A topic's or table bucket's ARN: new statements' resource. */
  resource?: string;
  /** The JSON's placeholder, when it's empty. */
  placeholder?: string;
  /** No statements left means no policy: the document is cleared. */
  emptyIsNone?: boolean;
}) {
  load();
  const [mode, setModeSignal] = createSignal<"visual" | "json">(localStorage.getItem(MODE_KEY) === "json" ? "json" : "visual");
  const setMode = (m: "visual" | "json") => {
    setModeSignal(m);
    localStorage.setItem(MODE_KEY, m);
  };
  const parsed = createMemo((): { doc: Json } | { error: string } => {
    const text = props.document.trim();
    if (!text) return { doc: { Version: "2012-10-17", Statement: [] } };
    try {
      const doc = JSON.parse(text);
      if (!isObject(doc)) return { error: "The document isn't a JSON object." };
      if (doc.Statement !== undefined && !isObject(doc.Statement) && !Array.isArray(doc.Statement)) {
        return { error: "Its Statement isn't a statement or a list of them." };
      }
      return { doc };
    } catch (e) {
      return { error: `The document isn't valid JSON: ${(e as Error).message}` };
    }
  });
  const doc = () => ("doc" in parsed() ? (parsed() as { doc: Json }).doc : null);
  const statements = () => list(doc()?.Statement) as Json[];
  const setStatements = (next: Json[]) => {
    const d = doc()!;
    const others = Object.keys(d).filter((k) => !["Version", "Statement"].includes(k));
    if (!next.length && props.emptyIsNone && !others.length) return props.setDocument("");
    props.setDocument(pretty(withField({ Version: "2012-10-17", ...d }, "Statement", next)));
  };
  const visual = () => mode() === "visual";
  return (
    <div class="policy-document">
      <div class="tabs" role="tablist">
        <button type="button" role="tab" classList={{ active: visual() }} aria-selected={visual()} onClick={() => setMode("visual")}>
          Visual
        </button>
        <button type="button" role="tab" classList={{ active: !visual() }} aria-selected={!visual()} onClick={() => setMode("json")}>
          JSON
        </button>
      </div>
      <Show
        when={visual()}
        fallback={
          <textarea
            class="policy"
            aria-label={props.label}
            spellcheck={false}
            readOnly={props.readOnly}
            disabled={props.disabled}
            placeholder={props.placeholder}
            value={props.document}
            onInput={(e) => props.setDocument(e.currentTarget.value)}
          />
        }
      >
        <Show
          when={doc()}
          fallback={
            <p class="error-text">
              {"error" in parsed() ? (parsed() as { error: string }).error : ""}{" "}
              <button type="button" class="small" onClick={() => setMode("json")}>
                Fix it in the JSON
              </button>
            </p>
          }
        >
          <fieldset class="policy-builder" disabled={props.readOnly || props.disabled}>
            <Show when={doc()!.Version !== "2012-10-17"}>
              <p class="warn-note small">
                The document's Version isn't <span class="mono">2012-10-17</span>, so policy variables (
                <span class="mono">{"${aws:username}"}</span>) are plain text.{" "}
                <button type="button" class="small" onClick={() => props.setDocument(pretty({ Version: "2012-10-17", ...withField(doc()!, "Version", undefined) }))}>
                  Set it
                </button>
              </p>
            </Show>
            <Show when={!statements().length}>
              <p class="subtle">No statements yet{props.emptyIsNone ? ": no policy" : ", so the policy allows nothing"}.</p>
            </Show>
            <Index each={statements()}>
              {(s, i) => (
                <StatementCard
                  statement={s()}
                  n={i + 1}
                  kind={props.kind}
                  buckets={props.buckets ?? []}
                  bucket={props.bucket}
                  set={(changed) => setStatements(statements().map((x, j) => (j === i ? changed : x)))}
                  remove={() => setStatements(statements().filter((_, j) => j !== i))}
                />
              )}
            </Index>
            <Show when={!props.readOnly}>
              <div class="form-row">
                <button type="button" class="small" onClick={() => setStatements([...statements(), newStatement(props.kind, props.bucket, props.resource)])}>
                  Add statement
                </button>
              </div>
            </Show>
          </fieldset>
        </Show>
      </Show>
    </div>
  );
}
