import { A, Navigate, Route, Router, type RouteSectionProps } from "@solidjs/router";
import { render } from "solid-js/web";
import { Show } from "solid-js";
import { api } from "./api";
import { Toasts, poll } from "./components/ui";
import { BucketBrowser, BucketList, ObjectPage } from "./pages/Buckets";
import Integrity from "./pages/Integrity";
import Jobs from "./pages/Jobs";
import Lifecycle from "./pages/Lifecycle";
import Overview from "./pages/Overview";
import Users from "./pages/Users";
import Accounts from "./pages/Accounts";
import SignIn from "./pages/SignIn";
import Storage from "./pages/Storage";
import "./styles.css";

const NAV: [string, string][] = [
  ["/", "Overview"],
  ["/storage", "Storage"],
  ["/integrity", "Integrity"],
  ["/jobs", "Jobs"],
  ["/buckets", "Buckets"],
  ["/users", "Users"],
  ["/accounts", "Accounts"],
  ["/sign-in", "Sign-in"],
];

/** A count next to the Integrity link, on every page: objects with lost data
 * (bad), else open findings (being looked into, or a node down). */
function IntegrityCount() {
  const integrity = poll(api.integrity, 30000);
  const lost = () => integrity.data()?.lost_objects ?? 0;
  const open = () => integrity.data()?.open_findings ?? 0;
  return (
    <Show when={lost() || open()}>
      <span
        class={"nav-count " + (lost() ? "bad" : "warn")}
        title={lost() ? `${lost()} objects with lost data` : `${open()} open findings`}
      >
        {lost() || open()}
      </span>
    </Show>
  );
}

function Layout(props: RouteSectionProps) {
  return (
    <>
      <header class="topbar">
        <A class="brand" href="/">
          <svg viewBox="0 0 32 32" aria-hidden="true">
            <ellipse cx="16" cy="27" rx="12" ry="4" />
            <ellipse cx="16" cy="19" rx="9" ry="3.6" />
            <ellipse cx="16" cy="12" rx="6.5" ry="3" />
            <ellipse cx="16" cy="6" rx="4" ry="2.4" />
          </svg>
          Cairn
        </A>
        <nav>
          {NAV.map(([href, label]) => (
            <A href={href} end={href === "/"} activeClass="active">
              {label}
              {href === "/integrity" && <IntegrityCount />}
            </A>
          ))}
        </nav>
      </header>
      <main>{props.children}</main>
      <Toasts />
    </>
  );
}

function NotFound() {
  return (
    <>
      <h1>Not found</h1>
      <p>
        There's no page here. <A href="/">Back to the overview</A>
      </p>
    </>
  );
}

render(
  () => (
    // Plain links (downloads) are left to the browser; only <A> navigates.
    <Router root={Layout} base="/_dashboard" explicitLinks>
      <Route path="/" component={Overview} />
      <Route path="/storage" component={Storage} />
      <Route path="/integrity" component={Integrity} />
      <Route path="/jobs" component={Jobs} />
      <Route path="/buckets" component={BucketList} />
      <Route path="/buckets/:bucket" component={BucketBrowser} />
      <Route path="/buckets/:bucket/object" component={ObjectPage} />
      <Route path="/buckets/:bucket/lifecycle" component={Lifecycle} />
      <Route path="/users" component={Users} />
      <Route path="/accounts" component={Accounts} />
      <Route path="/sign-in" component={SignIn} />
      <Route path="/roles" component={() => <Navigate href="/users" />} />
      <Route path="*" component={NotFound} />
    </Router>
  ),
  document.getElementById("root")!,
);
