//! SNS and S3's event notifications end to end, against a real Postgres:
//! topics as SNS makes them, subscriptions confirmed and delivered to over
//! HTTP (a receiver on loopback, which `notification-private-endpoints`
//! lets them reach), signed as SNS signs; and S3's events, from writes to
//! deliveries.

use std::sync::{Arc, Mutex, atomic::{AtomicU16, Ordering}};

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Request, Response, body::Bytes};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    signature::Verifier,
};
use serde_json::Value;

use super::{Params, Sns};
use crate::{
    App,
    notifications::{delivery, signing},
    packer,
    s3::access::{Access, Origin},
    users::{self, Principal},
};

/// What a request answered: its result, or its error's code and message.
type Answer = Result<String, (String, String)>;

async fn call(app: &Arc<App>, key: &str, action: &str, params: &[(&str, &str)]) -> Answer {
    let client = app.pool.get().await.unwrap();
    let principal = Principal::load(&client, key).await.unwrap().unwrap();
    let origin = Origin { peer: Some("127.0.0.1".parse().unwrap()), trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(&principal), &principal.account, &Method::POST, &HeaderMap::new(), "", &origin).unwrap();
    let mut sns = Sns { app, client: &client, principal: &principal, access: &mut access, base_url: "http://cairn.test".to_owned() };
    match sns.dispatch(action, &Params::of(params)).await {
        Ok(xml) => Ok(xml.unwrap_or_default()),
        Err(e) => Err((e.code.to_owned(), e.message)),
    }
}

fn ok(answer: Answer) -> String {
    answer.unwrap_or_else(|(code, message)| panic!("{code}: {message}"))
}

fn refused(answer: Answer, code: &str) -> String {
    match answer {
        Ok(xml) => panic!("not refused: {xml}"),
        Err((c, message)) => {
            assert_eq!(c, code, "{message}");
            message
        }
    }
}

/// The text of the first `<name>` element in `xml`.
fn element(xml: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let start = xml.find(&open).unwrap_or_else(|| panic!("no {name} in {xml}")) + open.len();
    let end = xml[start..].find(&format!("</{name}>")).unwrap() + start;
    xml[start..end].replace("&amp;", "&").replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">")
}

/// An attribute's value in a Get…Attributes answer.
fn attribute(xml: &str, key: &str) -> Option<String> {
    let at = xml.find(&format!("<key>{key}</key>"))?;
    Some(element(&xml[at..], "value"))
}

/// A receiver on loopback: what it was sent, and what it answers.
struct Receiver {
    url: String,
    received: Arc<Mutex<Vec<(HeaderMap, String)>>>,
    status: Arc<AtomicU16>,
}

impl Receiver {
    async fn start() -> Receiver {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(AtomicU16::new(200));
        let (r, s) = (received.clone(), status.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (r, s) = (r.clone(), s.clone());
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let (r, s) = (r.clone(), s.clone());
                        async move {
                            let headers = req.headers().clone();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            r.lock().unwrap().push((headers, String::from_utf8(body.to_vec()).unwrap()));
                            let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
                            *response.status_mut() = hyper::StatusCode::from_u16(s.load(Ordering::SeqCst)).unwrap();
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Receiver { url, received, status }
    }

    fn take(&self) -> Vec<(HeaderMap, Value)> {
        std::mem::take(&mut *self.received.lock().unwrap())
            .into_iter()
            .map(|(h, b)| (h, serde_json::from_str(&b).unwrap_or(Value::String(b))))
            .collect()
    }
}

/// Fans out and sends until nothing's left that's due.
async fn deliver(app: &App) {
    for _ in 0..20 {
        let fanned = delivery::fan_out(app).await.unwrap();
        let sent = delivery::send(app).await.unwrap();
        if fanned == 0 && sent == 0 {
            return;
        }
    }
}

/// Checks a message's signature, with the certificate its URL names.
async fn verify(app: &App, message: &Value) {
    let url = message["SigningCertURL"].as_str().unwrap();
    let path = &url[url.find("/SimpleNotificationService-").unwrap()..];
    let id = signing::certificate_id(path).unwrap();
    let pem = signing::certificate(&app.pool.get().await.unwrap(), id).await.unwrap().unwrap();
    let der = rustls::pki_types::pem::PemObject::from_pem_slice(pem.as_bytes()).map(|c: rustls::pki_types::CertificateDer| c.to_vec()).unwrap();
    // The certificate's public key: its SubjectPublicKeyInfo, found by its
    // RSA algorithm identifier.
    let spki = spki_of(&der);
    let key = rsa::PublicKey::from_public_key_der(&spki).unwrap();
    let fields = match message["Type"].as_str().unwrap() {
        "Notification" => signing::NOTIFICATION_FIELDS,
        _ => signing::CONFIRMATION_FIELDS,
    };
    let text = signing::string_to_sign(fields, |name| message.get(name).and_then(Value::as_str).map(str::to_owned));
    let signature = Signature::try_from(STANDARD.decode(message["Signature"].as_str().unwrap()).unwrap().as_slice()).unwrap();
    match message["SignatureVersion"].as_str().unwrap() {
        "1" => VerifyingKey::<sha1::Sha1>::new(key).verify(text.as_bytes(), &signature).unwrap(),
        _ => VerifyingKey::<sha2::Sha256>::new(key).verify(text.as_bytes(), &signature).unwrap(),
    }
}

/// A certificate's SubjectPublicKeyInfo (DER), for an RSA key: the SEQUENCE
/// around its rsaEncryption algorithm identifier.
fn spki_of(cert: &[u8]) -> Vec<u8> {
    const RSA_OID: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let oid = cert.windows(RSA_OID.len()).position(|w| w == RSA_OID).unwrap();
    // The SPKI's SEQUENCE starts before the algorithm's SEQUENCE (30 0d),
    // with a long-form length (30 82 xx xx).
    let start = oid - 2 - 4;
    assert_eq!(cert[start], 0x30);
    let len = ((cert[start + 2] as usize) << 8) | cert[start + 3] as usize;
    cert[start..start + 4 + len].to_vec()
}

async fn node() -> Option<Arc<App>> {
    let app = crate::e2e::node_with(packer::Config::default(), None).await?;
    let client = app.pool.get().await.unwrap();
    crate::settings::NOTIFICATION_PRIVATE_ENDPOINTS.set(&client, 1).await.unwrap();
    Some(app)
}

/// Topics as SNS makes them: CreateTopic again is the same topic, unless it
/// asks for other attributes or tags; what attributes take, and what they
/// show; DeleteTopic of one that isn't there.
#[tokio::test]
async fn topics_are_as_sns_makes_them() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true).await.unwrap();
    let (nobody, _) = users::create_for(&client, &account, "nobody", None, false).await.unwrap();
    let arn = format!("arn:aws:sns:us-east-1:{account}:events");

    let made = ok(call(&app, &admin, "CreateTopic", &[("Name", "events")]).await);
    assert_eq!(element(&made, "TopicArn"), arn);
    ok(call(&app, &admin, "CreateTopic", &[("Name", "events")]).await);
    let message = refused(
        call(&app, &admin, "CreateTopic", &[("Name", "events"), ("Attributes.entry.1.key", "DisplayName"), ("Attributes.entry.1.value", "x")]).await,
        "InvalidParameter",
    );
    assert_eq!(message, "Invalid parameter: Attributes Reason: Topic already exists with different attributes");
    let message = refused(call(&app, &admin, "CreateTopic", &[("Name", "events"), ("Tags.member.1.Key", "k"), ("Tags.member.1.Value", "v")]).await, "InvalidParameter");
    assert_eq!(message, "Invalid parameter: Tags Reason: Topic already exists with different tags");
    for bad in ["a.b", "a b", "x!", ""] {
        let message = refused(call(&app, &admin, "CreateTopic", &[("Name", bad)]).await, "InvalidParameter");
        assert_eq!(message, "Invalid parameter: Topic Name");
    }
    let message = refused(
        call(&app, &admin, "CreateTopic", &[("Name", "other"), ("Attributes.entry.1.key", "Bogus"), ("Attributes.entry.1.value", "1")]).await,
        "InvalidParameter",
    );
    assert_eq!(message, "Invalid parameter: Attributes Reason: Unknown attribute Bogus");

    let attributes = ok(call(&app, &admin, "GetTopicAttributes", &[("TopicArn", &arn)]).await);
    assert_eq!(attribute(&attributes, "Owner").unwrap(), account);
    assert_eq!(attribute(&attributes, "SubscriptionsPending").unwrap(), "0");
    assert!(attribute(&attributes, "Policy").unwrap().contains("__default_policy_ID"));
    assert!(attribute(&attributes, "EffectiveDeliveryPolicy").unwrap().contains("\"numRetries\":3"));
    assert_eq!(attribute(&attributes, "DeliveryPolicy"), None);

    let set = |name: &'static str, value: &'static str| {
        let (app, admin, arn) = (app.clone(), admin.clone(), arn.clone());
        async move { call(&app, &admin, "SetTopicAttributes", &[("TopicArn", &arn), ("AttributeName", name), ("AttributeValue", value)]).await }
    };
    ok(set("DisplayName", "Events").await);
    assert_eq!(refused(set("Owner", "1").await, "InvalidParameter"), "Invalid parameter: AttributeName");
    assert_eq!(refused(set("Bogus", "1").await, "InvalidParameter"), "Invalid parameter: AttributeName");
    assert_eq!(refused(set("Policy", "{}").await, "InvalidParameter"), "Invalid parameter: Policy Error: null");
    assert_eq!(
        refused(set("SignatureVersion", "3").await, "InvalidParameter"),
        "Invalid parameter: SignatureVersion: Invalid value '[3]'. Must be 1 or 2."
    );
    assert_eq!(
        refused(set("DeliveryPolicy", r#"{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":1,"maxDelayTarget":1,"numRetries":101}}}"#).await, "InvalidParameter"),
        "Invalid parameter: DeliveryPolicy: http.defaultHealthyRetryPolicy.numRetries must be less than or equal to 100"
    );
    ok(set("DeliveryPolicy", r#"{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":5,"maxDelayTarget":20,"numRetries":6}}}"#).await);
    let attributes = ok(call(&app, &admin, "GetTopicAttributes", &[("TopicArn", &arn)]).await);
    assert_eq!(attribute(&attributes, "DisplayName").unwrap(), "Events");
    assert!(attribute(&attributes, "DeliveryPolicy").unwrap().contains("\"numRetries\":6"));

    // Errors for topics that aren't there, or ARNs that aren't.
    let missing = format!("arn:aws:sns:us-east-1:{account}:missing");
    assert_eq!(refused(call(&app, &admin, "GetTopicAttributes", &[("TopicArn", &missing)]).await, "NotFound"), "Topic does not exist");
    assert_eq!(
        refused(call(&app, &admin, "GetTopicAttributes", &[("TopicArn", "nonsense")]).await, "InvalidParameter"),
        "Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not 1"
    );
    ok(call(&app, &admin, "DeleteTopic", &[("TopicArn", &missing)]).await);

    // Tags.
    ok(call(&app, &admin, "TagResource", &[("ResourceArn", &arn), ("Tags.member.1.Key", "team"), ("Tags.member.1.Value", "red")]).await);
    let tags = ok(call(&app, &admin, "ListTagsForResource", &[("ResourceArn", &arn)]).await);
    assert!(tags.contains("<Key>team</Key><Value>red</Value>"), "{tags}");
    ok(call(&app, &admin, "UntagResource", &[("ResourceArn", &arn), ("TagKeys.member.1", "team")]).await);

    // A user its policies don't allow SNS, whatever the default policy says.
    let message = refused(call(&app, &nobody, "GetTopicAttributes", &[("TopicArn", &arn)]).await, "AuthorizationError");
    assert!(message.contains("is not authorized to perform: SNS:GetTopicAttributes"), "{message}");

    let listed = ok(call(&app, &admin, "ListTopics", &[]).await);
    assert!(listed.contains(&format!("<TopicArn>{arn}</TopicArn>")), "{listed}");
    ok(call(&app, &admin, "DeleteTopic", &[("TopicArn", &arn)]).await);
    assert_eq!(refused(call(&app, &admin, "GetTopicAttributes", &[("TopicArn", &arn)]).await, "NotFound"), "Topic does not exist");
}

/// A subscription is confirmed by its token, delivered to, signed, retried
/// on a 5xx but not on a 4xx, and unsubscribed; a GET of its
/// `UnsubscribeURL` sends a confirmation whose token restores it.
#[tokio::test]
async fn subscriptions_are_confirmed_and_delivered_to() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true).await.unwrap();
    let receiver = Receiver::start().await;
    let arn = element(&ok(call(&app, &admin, "CreateTopic", &[("Name", "t")]).await), "TopicArn");

    let message = refused(call(&app, &admin, "Subscribe", &[("TopicArn", &arn), ("Protocol", "sqs"), ("Endpoint", "x")]).await, "InvalidParameter");
    assert_eq!(message, "Invalid parameter: Amazon SNS does not support this protocol string: sqs");
    let message = refused(call(&app, &admin, "Subscribe", &[("TopicArn", &arn), ("Protocol", "https"), ("Endpoint", &receiver.url)]).await, "InvalidParameter");
    assert_eq!(message, "Invalid parameter: Endpoint must match the specified protocol");

    let answer = ok(call(&app, &admin, "Subscribe", &[("TopicArn", &arn), ("Protocol", "http"), ("Endpoint", &receiver.url)]).await);
    assert_eq!(element(&answer, "SubscriptionArn"), "pending confirmation");
    deliver(&app).await;
    let got = receiver.take();
    assert_eq!(got.len(), 1);
    let (headers, confirmation) = &got[0];
    assert_eq!(headers["x-amz-sns-message-type"], "SubscriptionConfirmation");
    assert_eq!(headers["user-agent"], delivery::USER_AGENT);
    assert!(headers.get("x-amz-sns-subscription-arn").is_none());
    assert_eq!(confirmation["TopicArn"], arn.as_str());
    let token = confirmation["Token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 256);
    assert!(confirmation["SubscribeURL"].as_str().unwrap().starts_with("http://cairn.test/?Action=ConfirmSubscription&TopicArn="));
    verify(&app, confirmation).await;

    assert_eq!(refused(call(&app, &admin, "ConfirmSubscription", &[("TopicArn", &arn), ("Token", "00")]).await, "InvalidParameter"), "Invalid parameter: Token");
    let confirmed = ok(call(&app, &admin, "ConfirmSubscription", &[("TopicArn", &arn), ("Token", &token)]).await);
    let sub = element(&confirmed, "SubscriptionArn");
    assert!(sub.starts_with(&format!("{arn}:")));
    // Again, with the same token: the same subscription.
    assert_eq!(element(&ok(call(&app, &admin, "ConfirmSubscription", &[("TopicArn", &arn), ("Token", &token)]).await), "SubscriptionArn"), sub);

    let attributes = ok(call(&app, &admin, "GetSubscriptionAttributes", &[("SubscriptionArn", &sub)]).await);
    assert_eq!(attribute(&attributes, "PendingConfirmation").unwrap(), "false");
    assert_eq!(attribute(&attributes, "RawMessageDelivery").unwrap(), "false");

    // Published, with a subject and an attribute.
    let published = ok(call(
        &app,
        &admin,
        "Publish",
        &[
            ("TopicArn", &arn),
            ("Message", "hello"),
            ("Subject", "subj"),
            ("MessageAttributes.entry.1.Name", "a"),
            ("MessageAttributes.entry.1.Value.DataType", "String"),
            ("MessageAttributes.entry.1.Value.StringValue", "v"),
        ],
    )
    .await);
    deliver(&app).await;
    let got = receiver.take();
    assert_eq!(got.len(), 1);
    let (headers, notification) = &got[0];
    assert_eq!(headers["x-amz-sns-subscription-arn"], sub.as_str());
    assert_eq!(headers["content-type"], "text/plain; charset=UTF-8");
    assert_eq!(notification["MessageId"], element(&published, "MessageId").as_str());
    assert_eq!(notification["Subject"], "subj");
    assert_eq!(notification["MessageAttributes"]["a"]["Value"], "v");
    verify(&app, notification).await;

    // A 5xx is retried (as the policy says, later); a 4xx isn't.
    receiver.status.store(500, Ordering::SeqCst);
    ok(call(&app, &admin, "Publish", &[("TopicArn", &arn), ("Message", "again")]).await);
    deliver(&app).await;
    assert_eq!(receiver.take().len(), 1);
    assert_eq!(crate::e2e::query_i64(&app, "SELECT count(*) FROM sns_deliveries WHERE attempt = 1").await, 1);
    client.execute("UPDATE sns_deliveries SET next_at = now()", &[]).await.unwrap();
    receiver.status.store(404, Ordering::SeqCst);
    deliver(&app).await;
    assert_eq!(receiver.take().len(), 1);
    assert_eq!(crate::e2e::query_i64(&app, "SELECT count(*) FROM sns_deliveries").await, 0);
    receiver.status.store(200, Ordering::SeqCst);

    // Raw delivery: the message alone.
    ok(call(&app, &admin, "SetSubscriptionAttributes", &[("SubscriptionArn", &sub), ("AttributeName", "RawMessageDelivery"), ("AttributeValue", "true")]).await);
    assert_eq!(
        refused(call(&app, &admin, "SetSubscriptionAttributes", &[("SubscriptionArn", &sub), ("AttributeName", "RawMessageDelivery"), ("AttributeValue", "yes")]).await, "InvalidParameter"),
        "Invalid parameter: RawMessageDelivery: Invalid value [yes]. Must be true or false."
    );
    ok(call(&app, &admin, "Publish", &[("TopicArn", &arn), ("Message", "raw")]).await);
    deliver(&app).await;
    let got = receiver.take();
    assert_eq!(got[0].1, Value::String("raw".into()));
    assert_eq!(got[0].0["x-amz-sns-rawdelivery"], "true");

    // A GET of the UnsubscribeURL: deleted, and a confirmation sent, whose
    // token restores it.
    let params = Params::of(&[("Action", "Unsubscribe"), ("SubscriptionArn", &sub)]);
    super::subscriptions::unsubscribe_unsigned(&app, &params, "http://cairn.test").await.unwrap_or_else(|e| panic!("{}", e.message));
    let listed = ok(call(&app, &admin, "ListSubscriptionsByTopic", &[("TopicArn", &arn)]).await);
    assert_eq!(element(&listed, "SubscriptionArn"), "Deleted");
    deliver(&app).await;
    let got = receiver.take();
    assert_eq!(got[0].0["x-amz-sns-message-type"], "UnsubscribeConfirmation");
    verify(&app, &got[0].1).await;
    ok(call(&app, &admin, "Publish", &[("TopicArn", &arn), ("Message", "nobody")]).await);
    deliver(&app).await;
    assert!(receiver.take().is_empty());
    assert_eq!(element(&ok(call(&app, &admin, "ConfirmSubscription", &[("TopicArn", &arn), ("Token", &token)]).await), "SubscriptionArn"), sub);

    // Unsubscribe: sends nothing; again is no error.
    ok(call(&app, &admin, "Unsubscribe", &[("SubscriptionArn", &sub)]).await);
    ok(call(&app, &admin, "Unsubscribe", &[("SubscriptionArn", &sub)]).await);
    deliver(&app).await;
    assert!(receiver.take().is_empty());
}

/// S3's events: a configuration is taken only for a topic whose policy lets
/// S3 publish; it's tested; and a bucket's writes are delivered as S3
/// writes its records.
#[tokio::test]
async fn bucket_events_are_delivered() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true).await.unwrap();
    let receiver = Receiver::start().await;
    let arn = element(&ok(call(&app, &admin, "CreateTopic", &[("Name", "events")]).await), "TopicArn");
    ok(call(&app, &admin, "Subscribe", &[("TopicArn", &arn), ("Protocol", "http"), ("Endpoint", &receiver.url)]).await);
    deliver(&app).await;
    let token = receiver.take()[0].1["Token"].as_str().unwrap().to_owned();
    ok(call(&app, &admin, "ConfirmSubscription", &[("TopicArn", &arn), ("Token", &token)]).await);

    let bucket = crate::e2e::BUCKET;
    let config = format!(
        "<NotificationConfiguration><TopicConfiguration><Id>all</Id><Topic>{arn}</Topic>\
         <Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event>\
         <Filter><S3Key><FilterRule><Name>prefix</Name><Value>n/</Value></FilterRule></S3Key></Filter>\
         </TopicConfiguration></NotificationConfiguration>"
    );
    // The default policy doesn't let S3 publish.
    let response = crate::s3::buckets::notification::put(&app, bucket, Bytes::from(config.clone())).await.unwrap();
    assert_eq!(response.status(), 400);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("Unable to validate the following destination configurations"), "{body}");
    assert!(body.contains(&format!("<ArgumentName1>{arn}</ArgumentName1>")), "{body}");
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"s3.amazonaws.com"}},"Action":"SNS:Publish","Resource":"{arn}","Condition":{{"ArnLike":{{"aws:SourceArn":"arn:aws:s3:::{bucket}"}}}}}}]}}"#
    );
    ok(call(&app, &admin, "SetTopicAttributes", &[("TopicArn", &arn), ("AttributeName", "Policy"), ("AttributeValue", &policy)]).await);
    let response = crate::s3::buckets::notification::put(&app, bucket, Bytes::from(config)).await.unwrap();
    assert_eq!(response.status(), 200);
    let shown = crate::s3::buckets::notification::get(&app, bucket).await.unwrap().into_body().collect().await.unwrap().to_bytes();
    let shown = String::from_utf8_lossy(&shown).to_string();
    assert!(shown.contains("<Id>all</Id>") && shown.contains("<Name>Prefix</Name><Value>n/</Value>"), "{shown}");
    deliver(&app).await;
    let got = receiver.take();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1["Subject"], "Amazon S3 Notification");
    let test: Value = serde_json::from_str(got[0].1["Message"].as_str().unwrap()).unwrap();
    assert_eq!(test["Event"], "s3:TestEvent");
    assert_eq!(test["Bucket"], bucket);

    crate::e2e::put(&app, "n/ü a", b"hello".to_vec()).await;
    crate::e2e::put(&app, "other/x", b"not this".to_vec()).await;
    crate::e2e::delete(&app, "n/ü a").await;
    deliver(&app).await;
    let got = receiver.take();
    assert_eq!(got.len(), 2, "{got:?}");
    let records: Vec<Value> = got
        .iter()
        .map(|(_, m)| serde_json::from_str::<Value>(m["Message"].as_str().unwrap()).unwrap()["Records"][0].clone())
        .collect();
    let put = records.iter().find(|r| r["eventName"] == "ObjectCreated:Put").expect("a put's event");
    assert_eq!(put["s3"]["object"]["key"], "n/%C3%BC+a");
    assert_eq!(put["s3"]["object"]["size"], 5);
    assert_eq!(put["s3"]["object"]["eTag"], "5d41402abc4b2a76b9719d911017c592");
    assert_eq!(put["s3"]["configurationId"], "all");
    assert_eq!(put["s3"]["bucket"]["arn"], format!("arn:aws:s3:::{bucket}"));
    assert!(put["s3"]["object"].get("versionId").is_none());
    let deleted = records.iter().find(|r| r["eventName"] == "ObjectRemoved:Delete").expect("a delete's event");
    assert!(deleted["s3"]["object"].get("size").is_none());
    // Sequencers grow with a key's changes.
    assert!(deleted["s3"]["object"]["sequencer"].as_str().unwrap() > put["s3"]["object"]["sequencer"].as_str().unwrap());
    for (_, m) in &got {
        verify(&app, m).await;
    }

    // Revoking the policy drops events.
    ok(call(&app, &admin, "SetTopicAttributes", &[("TopicArn", &arn), ("AttributeName", "Policy"), ("AttributeValue", &super::default_policy(&account, &arn))]).await);
    crate::e2e::put(&app, "n/later", b"x".to_vec()).await;
    deliver(&app).await;
    assert!(receiver.take().is_empty());
    assert_eq!(crate::e2e::query_i64(&app, "SELECT count(*) FROM notification_events").await, 0);
}

/// I14 (`catalog.sql`): racing writes of a key each have their event, and
/// the events' sequencers follow the versions' commit order.
#[tokio::test]
async fn racing_writes_have_their_events_in_order() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let bucket = crate::e2e::BUCKET;
    client.query_one("SELECT pg_temp.cairn_set_versioning($1, 'enabled')", &[&bucket]).await.unwrap();
    client
        .execute(
            "INSERT INTO bucket_notifications (bucket, position, id, topic_arn, events)
             VALUES ($1, 0, 'all', 'arn:aws:sns:us-east-1:000000000000:none', '{s3:ObjectCreated:*,s3:ObjectRemoved:*}')",
            &[&bucket],
        )
        .await
        .unwrap();
    let writes: Vec<_> = (0..16)
        .map(|i| {
            let app = app.clone();
            tokio::spawn(async move {
                if i % 4 == 3 {
                    crate::e2e::delete(&app, "raced").await;
                } else {
                    crate::e2e::put(&app, "raced", vec![i as u8; 10]).await;
                }
            })
        })
        .collect();
    for w in writes {
        w.await.unwrap();
    }
    let by_sequencer: Vec<String> = client
        .query("SELECT version_id FROM notification_events WHERE key = 'raced' ORDER BY sequencer", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let by_commit: Vec<String> =
        client.query("SELECT version_id FROM objects WHERE key = 'raced' ORDER BY id", &[]).await.unwrap().iter().map(|r| r.get(0)).collect();
    assert_eq!(by_sequencer.len(), 16);
    assert_eq!(by_sequencer, by_commit);
}

/// Another account's topic, as AWS's: what its policy allows that account
/// (AddPermission), if the caller's own policies allow it too; nothing
/// else, and it's not in the caller's ListTopics.
#[tokio::test]
async fn other_accounts_use_topics_as_their_policies_allow() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true).await.unwrap();
    let made = crate::organizations::create(&client, &account, "Team D", "team-d@example.com", "OrganizationAccountAccessRole").await.unwrap();
    let member = made.account_id.unwrap();
    let (mel, _) = users::create_for(&client, &member, "mel", None, false).await.unwrap();
    let allowed = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:*","Resource":"*"}]}"#;
    users::put_policy(&client, &member, "mel", "p", allowed).await.unwrap();
    let (nora, _) = users::create_for(&client, &member, "nora", None, false).await.unwrap();
    let arn = element(&ok(call(&app, &admin, "CreateTopic", &[("Name", "shared")]).await), "TopicArn");

    // Its default policy is its own account's.
    refused(call(&app, &mel, "GetTopicAttributes", &[("TopicArn", &arn)]).await, "AuthorizationError");
    ok(call(
        &app,
        &admin,
        "AddPermission",
        &[
            ("TopicArn", &arn),
            ("Label", "team-d"),
            ("AWSAccountId.member.1", &member),
            ("ActionName.member.1", "GetTopicAttributes"),
            ("ActionName.member.2", "Subscribe"),
        ],
    )
    .await);
    let attributes = ok(call(&app, &mel, "GetTopicAttributes", &[("TopicArn", &arn)]).await);
    assert_eq!(attribute(&attributes, "Owner").as_deref(), Some(account.as_str()));
    // Not what the topic's policy doesn't allow, nor whom its own don't.
    refused(call(&app, &mel, "Publish", &[("TopicArn", &arn), ("Message", "hi")]).await, "AuthorizationError");
    refused(call(&app, &nora, "GetTopicAttributes", &[("TopicArn", &arn)]).await, "AuthorizationError");
    let listed = ok(call(&app, &mel, "ListTopics", &[]).await);
    assert!(!listed.contains(&arn), "{listed}");
    // An account that isn't the organization's has no topics.
    let elsewhere = arn.replace(&account, "999999999999");
    refused(call(&app, &mel, "GetTopicAttributes", &[("TopicArn", &elsewhere)]).await, "InvalidClientTokenId");
}
