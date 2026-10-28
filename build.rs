//! Embeds the dashboard's UI: every file in `ui/dist`, as built by `npm run
//! build` in `ui/`. Cairn doesn't build without it: run `npm ci && npm run
//! build` there first (`build-release.sh` does). It isn't built from here, so
//! that building Cairn never runs npm, say whenever an editor re-runs build
//! scripts.

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// What the UI is built from: if any of it changed after the last build, the
/// build is stale.
const SOURCES: &[&str] = &[
    "ui/src",
    "ui/public",
    "ui/index.html",
    "ui/package.json",
    "ui/package-lock.json",
    "ui/vite.config.ts",
    "ui/tsconfig.json",
];

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = root.join("ui/dist");
    // Cargo scans a directory for changes to anything in it.
    println!("cargo:rerun-if-changed=ui/dist");
    for source in SOURCES {
        println!("cargo:rerun-if-changed={source}");
    }
    let Ok(built) = dist.join("index.html").metadata().and_then(|m| m.modified()) else {
        eprintln!(
            "error: the dashboard's UI isn't built (no ui/dist/index.html).\n\
             Build it first, with Node.js 26 or later: cd ui && npm ci && npm run build"
        );
        std::process::exit(1);
    };
    let newest = SOURCES.iter().filter_map(|s| newest(&root.join(s))).max();
    if newest.is_some_and(|newest| newest > built) {
        println!(
            "cargo:warning=ui/dist is older than the UI's sources, so the dashboard may be \
             out of date; run `npm run build` in ui/"
        );
    }
    let mut files = Vec::new();
    walk(&dist, &mut files);
    files.sort();
    let mut out = String::from("static ASSETS: &[Asset] = &[\n");
    for file in &files {
        let path = file.strip_prefix(&dist).unwrap();
        let path = format!("/{}", path.to_str().expect("UTF-8 file names").replace('\\', "/"));
        writeln!(
            out,
            "    Asset {{ path: {path:?}, content_type: {:?}, body: include_bytes!({file:?}) }},",
            content_type(file),
        )
        .unwrap();
    }
    out.push_str("];\n");
    let target = Path::new(&std::env::var("OUT_DIR").unwrap()).join("dashboard_assets.rs");
    std::fs::write(target, out).unwrap();
}

/// When anything at `path` (a file, or a directory and everything in it) was
/// last changed; `None` if there's nothing there.
fn newest(path: &Path) -> Option<SystemTime> {
    let own = path.metadata().and_then(|m| m.modified()).ok()?;
    if !path.is_dir() {
        return Some(own);
    }
    let entries = std::fs::read_dir(path).ok()?;
    entries
        .filter_map(|e| newest(&e.ok()?.path()))
        .chain([own])
        .max()
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, files);
        } else {
            files.push(path);
        }
    }
}

fn content_type(file: &Path) -> &'static str {
    match file.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
