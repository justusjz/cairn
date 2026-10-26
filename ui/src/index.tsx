import { A, Route, Router, type RouteSectionProps } from "@solidjs/router";
import { render } from "solid-js/web";
import { Toasts } from "./components/ui";
import { BucketBrowser, BucketList, ObjectPage } from "./pages/Buckets";
import Jobs from "./pages/Jobs";
import Overview from "./pages/Overview";
import Roles from "./pages/Roles";
import Storage from "./pages/Storage";
import "./styles.css";

const NAV: [string, string][] = [
  ["/", "Overview"],
  ["/storage", "Storage"],
  ["/jobs", "Jobs"],
  ["/buckets", "Buckets"],
  ["/roles", "Roles"],
];

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
    <Router root={Layout} explicitLinks>
      <Route path="/" component={Overview} />
      <Route path="/storage" component={Storage} />
      <Route path="/jobs" component={Jobs} />
      <Route path="/buckets" component={BucketList} />
      <Route path="/buckets/:bucket" component={BucketBrowser} />
      <Route path="/buckets/:bucket/object" component={ObjectPage} />
      <Route path="/roles" component={Roles} />
      <Route path="*" component={NotFound} />
    </Router>
  ),
  document.getElementById("root")!,
);
