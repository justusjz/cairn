//! The CLI's commands about the cluster (`cairn user`, `account`, `oidc`,
//! `bucket-policy`, `config` and `node`) run on a node, not against the
//! database: the CLI sends the command it parsed to a node's peer endpoint
//! (`--peer-url`, as `cairn serve` has it), which carries it out as the CLI
//! used to, and answers with what to print. So the CLI needs no database
//! credentials, and the node does what only it knows how to: make enrollment
//! links from its console's URL, make a new user's identity in the KMS, go by
//! a changed setting at once.
//!
//! The peer endpoint is unauthenticated, for the private network only (see
//! `peer`). So that no web page opened on that network can send commands, a
//! request must carry the [`HEADER`] (which a cross-site request can't send
//! without a CORS preflight, which the endpoint never allows), and name a
//! host no other site can be made to resolve to the node (DNS rebinding): an
//! IP address, `localhost`, or the host of the node's own peer URL.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use clap::Args;
use http_body_util::{BodyExt, Full};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde::{Deserialize, Serialize};

use crate::{App, db::Cached};

/// The header a command must come with: the version of the CLI that sent it.
pub const HEADER: &str = "x-cairn-cli";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which node a command goes to.
#[derive(Args, Debug, Default, Clone)]
pub struct Remote {
    /// The peer URL of the node to run the command on, as `cairn serve`
    /// has it (that of the node on this host, by default).
    #[arg(long, env = "CAIRN_PEER_URL", default_value = "http://127.0.0.1:9431", global = true)]
    pub peer_url: String,
}

/// A command, as the CLI sends it.
#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    User(crate::roles::RoleArgs),
    Account(crate::accounts::AccountArgs),
    Oidc(crate::console::oidc::OidcArgs),
    BucketPolicy(crate::s3::buckets::policy::BucketPolicyArgs),
    Config(crate::settings::ConfigArgs),
    Node(crate::nodes::NodeArgs),
}

/// What a command printed, and how it failed, if it did.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

impl Output {
    /// A line of what it prints.
    pub fn line(&mut self, line: impl std::fmt::Display) {
        use std::fmt::Write;
        writeln!(self.stdout, "{line}").unwrap();
    }

    /// A warning, for stderr.
    pub fn warn(&mut self, warning: impl std::fmt::Display) {
        use std::fmt::Write;
        writeln!(self.stderr, "warning: {warning}").unwrap();
    }
}

/// Prints a line of a command's output (`println!`, into an [`Output`]).
macro_rules! outln {
    ($out:expr, $($arg:tt)*) => {
        $out.line(format_args!($($arg)*))
    };
}
pub(crate) use outln;

/// Carries out `command` on node `app`.
pub async fn run(app: &Arc<App>, command: Command) -> Output {
    let mut out = Output::default();
    let result = match command {
        Command::User(args) => crate::roles::run(app, args, &mut out).await,
        Command::Account(args) => crate::accounts::run(app, args, &mut out).await,
        Command::Oidc(args) => crate::console::oidc::run(app, args, &mut out).await,
        Command::BucketPolicy(args) => crate::s3::buckets::policy::run(app, args, &mut out).await,
        Command::Config(args) => crate::settings::run(app, args, &mut out).await,
        Command::Node(args) => crate::nodes::run(app, args, &mut out).await,
    };
    if let Err(e) = result {
        if !matches!(e.downcast_ref::<crate::roles::Invalid>(), Some(_)) {
            eprintln!("admin: command failed: {e:#}");
        }
        out.error = Some(format!("{e:#}"));
    }
    out
}

/// `POST /admin`, on the peer endpoint: carries out a command.
pub async fn serve(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    let refused = |status: StatusCode, why: String| (status, why).into_response();
    let Some(version) = headers.get(HEADER).and_then(|v| v.to_str().ok()) else {
        return refused(StatusCode::FORBIDDEN, format!("commands must come with the {HEADER} header"));
    };
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    match own_host(&app).await {
        Ok(own) if known_host(host, own.as_deref()) => {}
        Ok(_) => {
            return refused(
                StatusCode::FORBIDDEN,
                "commands are only taken at an IP address, localhost, or the node's peer URL".into(),
            );
        }
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, format!("{e:#}")),
    }
    let command: Command = match serde_json::from_slice(&body) {
        Ok(command) => command,
        Err(e) if version != VERSION => {
            return refused(
                StatusCode::BAD_REQUEST,
                format!("this node runs Cairn {VERSION}, which doesn't take this command of Cairn {version}: {e}"),
            );
        }
        Err(e) => return refused(StatusCode::BAD_REQUEST, format!("not a command: {e}")),
    };
    Json(run(&app, command).await).into_response()
}

/// The host of the node's own peer URL.
async fn own_host(app: &App) -> anyhow::Result<Option<String>> {
    let client = app.pool.get().await?;
    let url: String = client.query_one_cached("SELECT peer_url FROM nodes WHERE id = $1", &[&app.node]).await?.get(0);
    Ok(url.parse::<axum::http::Uri>().ok().and_then(|uri| uri.host().map(str::to_ascii_lowercase)))
}

/// Whether `host` (a `Host` header, maybe with a port) is an IP address,
/// `localhost` (or a name under it, which browsers resolve to loopback
/// themselves), or `own`.
fn known_host(host: &str, own: Option<&str>) -> bool {
    let name = match host.strip_prefix('[') {
        // An IPv6 address, which must be in brackets.
        Some(rest) => {
            return rest.split_once(']').is_some_and(|(ip, port)| {
                (port.is_empty() || port.starts_with(':')) && ip.parse::<Ipv6Addr>().is_ok()
            });
        }
        None => host.split_once(':').map_or(host, |(name, _)| name),
    };
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let own = own.map(|p| p.strip_suffix('.').unwrap_or(p));
    !name.is_empty()
        && (name.parse::<IpAddr>().is_ok() || name == "localhost" || name.ends_with(".localhost") || own == Some(&name))
}

/// Sends `command` to the node at `remote`, prints what it printed, and
/// fails as it did.
pub async fn send(remote: &Remote, command: Command) -> anyhow::Result<()> {
    let base = remote.peer_url.trim_end_matches('/');
    let body = serde_json::to_vec(&command)?;
    let request = hyper::Request::post(format!("{base}/admin"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(HEADER, VERSION)
        .body(Full::new(Bytes::from(body)))?;
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = client
        .request(request)
        .await
        .map_err(|e| anyhow::Error::new(e).context(format!("can't reach the node at {base} (--peer-url, CAIRN_PEER_URL)")))?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        anyhow::bail!("the node at {base} refused the command: {}", String::from_utf8_lossy(&body).trim());
    }
    let output: Output = serde_json::from_slice(&body)
        .map_err(|e| anyhow::anyhow!("the node at {base} answered something else than a command's output: {e}"))?;
    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    match output.error {
        None => Ok(()),
        Some(error) => anyhow::bail!(error),
    }
}

/// A document a command takes: the contents of `file` (`-`: stdin), read
/// where the CLI runs.
pub fn read_document(file: &str) -> anyhow::Result<String> {
    Ok(match file {
        "-" => std::io::read_to_string(std::io::stdin())?,
        path => std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_hosts_that_cant_be_rebound() {
        for host in [
            "10.0.0.1",
            "10.0.0.1:9431",
            "[::1]:9431",
            "[fe80::1]",
            "localhost:9431",
            "LocalHost",
            "app.localhost",
            "node-a.internal:9431",
            "node-a.internal.",
        ] {
            assert!(known_host(host, Some("node-a.internal")), "{host}");
        }
        for host in [
            "",
            "evil.example",
            "evil.example:9431",
            "localhost.evil.example",
            "node-a.internal.evil.example",
            "[::1",
            "[evil.example]",
            "[::1]evil",
        ] {
            assert!(!known_host(host, Some("node-a.internal")), "{host}");
        }
        assert!(!known_host("node-a.internal", None));
    }
}

#[cfg(test)]
mod e2e {
    use clap::Parser;
    use tower::ServiceExt;

    use super::*;
    use crate::e2e::{BUCKET, node_with};

    async fn node() -> Option<Arc<App>> {
        node_with(crate::packer::Config::default(), None).await
    }

    /// A request to `/admin`, with `host` and `headers`.
    fn request(host: &str, cli: Option<&str>, body: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        let mut req = axum::http::Request::post("/admin").header(header::HOST, host);
        if let Some(version) = cli {
            req = req.header(HEADER, version);
        }
        req.body(axum::body::Body::from(body)).unwrap()
    }

    async fn answer(app: &Arc<App>, req: axum::http::Request<axum::body::Body>) -> (StatusCode, Vec<u8>) {
        let resp = crate::peer::router(app.clone()).oneshot(req).await.unwrap();
        let status = resp.status();
        (status, resp.into_body().collect().await.unwrap().to_bytes().to_vec())
    }

    /// Runs `cairn <args>` on node `app`, as the CLI sends it.
    async fn cairn(app: &Arc<App>, args: &[&str]) -> Output {
        let cli = crate::Cli::try_parse_from(std::iter::once("cairn").chain(args.iter().copied())).unwrap();
        let (_, command) = crate::remote_command(cli.command).unwrap();
        let body = serde_json::to_vec(&command).unwrap();
        let (status, body) = answer(app, request("127.0.0.1:9431", Some(VERSION), body)).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    /// The CLI's commands run on the node it names, which says what to print.
    #[tokio::test]
    async fn runs_the_clis_commands() {
        let Some(app) = node().await else { return };
        let out = cairn(&app, &["user", "create", "cli-ada", "--admin"]).await;
        assert_eq!(out.error, None);
        assert!(out.stdout.starts_with("access key: cli-ada\nsecret key: "), "{}", out.stdout);
        let out = cairn(&app, &["user", "list"]).await;
        assert!(out.stdout.contains("cli-ada (admin)"), "{}", out.stdout);
        // Its failures, as the CLI prints them.
        let out = cairn(&app, &["user", "delete", "nobody"]).await;
        assert_eq!(out.error.as_deref(), Some("no user named \"nobody\""));

        // Enrollment links: this node serves no console, so only the path.
        let out = cairn(&app, &["user", "enroll", "cli-ada"]).await;
        assert!(out.stdout.starts_with("/enroll#"), "{}", out.stdout);
        assert!(out.stderr.contains("serves no console"), "{}", out.stderr);
        let out = cairn(&app, &["account", "create", "cli-co"]).await;
        assert!(out.stdout.starts_with("account cli-co: "), "{}", out.stdout);
        let out = cairn(&app, &["user", "--account", "cli-co", "create", "cli-ada"]).await;
        assert_eq!(out.error, None, "names are the account's");
        assert!(cairn(&app, &["account", "enroll", "cli-co"]).await.stdout.starts_with("/enroll#"));

        // Documents are read where the CLI runs, and sent along.
        let file = std::env::temp_dir().join(format!("cairn-policy-{}.json", uuid::Uuid::new_v4()));
        let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListBucket","Resource":"*"}]}"#;
        std::fs::write(&file, document).unwrap();
        let path = file.to_str().unwrap();
        let out = cairn(&app, &["user", "policy", "put", "cli-ada", "nolist", path]).await;
        assert_eq!(out.error, None);
        assert_eq!(cairn(&app, &["user", "policy", "get", "cli-ada", "nolist"]).await.stdout.trim(), document);
        let bucket_policy = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::{BUCKET}"}}]}}"#
        );
        std::fs::write(&file, &bucket_policy).unwrap();
        assert_eq!(cairn(&app, &["bucket-policy", "put", BUCKET, path]).await.error, None);
        assert!(cairn(&app, &["bucket-policy", "get", BUCKET]).await.stdout.contains("s3:DeleteBucket"));
        std::fs::remove_file(&file).unwrap();

        // Settings: the node answering goes by them at once.
        let out = cairn(&app, &["config", "set", "parity-shards", "2"]).await;
        assert!(out.stderr.contains("warning: a blob takes 3 nodes"), "{}", out.stderr);
        assert_eq!(app.parity_shards(), 2);
        assert_eq!(cairn(&app, &["config", "unset", "parity-shards"]).await.error, None);
        assert_eq!(app.parity_shards(), 0);
        let out = cairn(&app, &["node", "list"]).await;
        assert!(out.stdout.contains("active"), "{}", out.stdout);
    }

    /// No web page can send commands: not without the header, which a
    /// cross-site request can't send, nor through a rebound name.
    #[tokio::test]
    async fn takes_commands_only_from_the_cli() {
        let Some(app) = node().await else { return };
        let body = || br#"{"Node":{"command":"List"}}"#.to_vec();
        assert_eq!(answer(&app, request("127.0.0.1:9431", Some(VERSION), body())).await.0, StatusCode::OK);
        assert_eq!(answer(&app, request("127.0.0.1:9431", None, body())).await.0, StatusCode::FORBIDDEN);
        assert_eq!(answer(&app, request("evil.example:9431", Some(VERSION), body())).await.0, StatusCode::FORBIDDEN);
        // Another version's command that this one doesn't take says so.
        let (status, body) = answer(&app, request("127.0.0.1:9431", Some("0.0.1"), b"{\"Frobnicate\":{}}".to_vec())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&body).contains("of Cairn 0.0.1"));
    }
}
