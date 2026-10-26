//! Embeds the dashboard's UI: every file in `ui/dist`, as built by `npm run
//! build` in `ui/`. If it isn't built, a placeholder page saying how to build
//! it is embedded instead, so that building Cairn never needs Node.

use std::fmt::Write;
use std::path::{Path, PathBuf};

fn main() {
    let dist = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ui/dist");
    // Cargo scans a directory for changes to anything in it.
    println!("cargo:rerun-if-changed=ui/dist");
    let mut files = Vec::new();
    if dist.join("index.html").is_file() {
        walk(&dist, &mut files);
        files.sort();
    } else {
        println!(
            "cargo:warning=ui/dist isn't built, so the dashboard is a placeholder; \
             run `npm ci && npm run build` in ui/"
        );
    }
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
    if files.is_empty() {
        writeln!(
            out,
            "    Asset {{ path: \"/index.html\", content_type: \"text/html; charset=utf-8\", body: {:?}.as_bytes() }},",
            PLACEHOLDER,
        )
        .unwrap();
    }
    out.push_str("];\n");
    let target = Path::new(&std::env::var("OUT_DIR").unwrap()).join("dashboard_assets.rs");
    std::fs::write(target, out).unwrap();
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

const PLACEHOLDER: &str = "<!doctype html><meta charset=utf-8><title>Cairn</title>\
<body>\
<h1>Cairn</h1><p>This build of Cairn has no dashboard: its UI wasn't built. \
Run <code>npm ci &amp;&amp; npm run build</code> in <code>ui/</code>, then build Cairn again.</p>";
