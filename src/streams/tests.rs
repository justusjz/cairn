//! Streams end to end, against a real Postgres: Kinesis's API on a node,
//! records written through flushes to the internal bucket and read back,
//! in order, and cleaned up after their retention or their stream.

use std::{collections::BTreeSet, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use super::kinesis::call;
use crate::{App, packer, users};

type Answer = Result<Value, (String, String)>;

fn ok(answer: Answer) -> Value {
    answer.unwrap_or_else(|(kind, message)| panic!("{kind}: {message}"))
}

fn refused(answer: Answer, kind: &str) -> String {
    match answer {
        Ok(value) => panic!("not refused: {value}"),
        Err((k, message)) => {
            assert_eq!(k, kind, "{message}");
            message
        }
    }
}

/// A node, and the access keys of an admin and of a user with no policies.
async fn node() -> Option<(Arc<App>, String, String)> {
    let app = crate::e2e::node_with(packer::Config::default(), None).await?;
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true)
        .await
        .unwrap();
    let (nobody, _) = users::create_for(&client, &account, "nobody", None, false)
        .await
        .unwrap();
    drop(client);
    Some((app, admin, nobody))
}

/// Every record of a shard, from its oldest, through GetRecords, `limit` at
/// a time: (sequence number, partition key, data).
async fn read_all(
    app: &Arc<App>,
    key: &str,
    stream: &str,
    shard: &str,
    limit: u64,
) -> Vec<(u64, String, Vec<u8>)> {
    let mut iterator = ok(call(
        app,
        key,
        "GetShardIterator",
        json!({ "StreamName": stream, "ShardId": shard, "ShardIteratorType": "TRIM_HORIZON" }),
    )
    .await)["ShardIterator"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut out = Vec::new();
    loop {
        let answer = ok(call(
            app,
            key,
            "GetRecords",
            json!({ "ShardIterator": iterator, "Limit": limit }),
        )
        .await);
        let records = answer["Records"].as_array().unwrap();
        if records.is_empty() {
            assert_eq!(answer["MillisBehindLatest"], 0);
            return out;
        }
        assert!(records.len() as u64 <= limit);
        for r in records {
            out.push((
                r["SequenceNumber"].as_str().unwrap().parse().unwrap(),
                r["PartitionKey"].as_str().unwrap().to_owned(),
                STANDARD.decode(r["Data"].as_str().unwrap()).unwrap(),
            ));
        }
        iterator = answer["NextShardIterator"].as_str().unwrap().to_owned();
    }
}

async fn put(
    app: &Arc<App>,
    key: &str,
    stream: &str,
    partition: &str,
    data: &[u8],
) -> (String, u64) {
    let answer = ok(call(
        app,
        key,
        "PutRecord",
        json!({ "StreamName": stream, "PartitionKey": partition, "Data": STANDARD.encode(data) }),
    )
    .await);
    (
        answer["ShardId"].as_str().unwrap().to_owned(),
        answer["SequenceNumber"].as_str().unwrap().parse().unwrap(),
    )
}

/// Streams as Kinesis makes them: created once per name, described, listed
/// with their shards' hash keys, their retention changed only in the
/// direction asked, deleted; and only as the caller's policies allow.
#[tokio::test]
async fn streams_are_made_described_and_deleted() {
    let Some((app, admin, nobody)) = node().await else {
        return;
    };
    let create = json!({ "StreamName": "orders", "ShardCount": 3 });
    ok(call(&app, &admin, "CreateStream", create.clone()).await);
    refused(
        call(&app, &admin, "CreateStream", create).await,
        "ResourceInUseException",
    );
    refused(
        call(
            &app,
            &nobody,
            "CreateStream",
            json!({ "StreamName": "x", "ShardCount": 1 }),
        )
        .await,
        "AccessDeniedException",
    );
    refused(
        call(
            &app,
            &admin,
            "CreateStream",
            json!({ "StreamName": "x", "ShardCount": 0 }),
        )
        .await,
        "InvalidArgumentException",
    );
    refused(
        call(
            &app,
            &admin,
            "CreateStream",
            json!({ "StreamName": "a/b", "ShardCount": 1 }),
        )
        .await,
        "ValidationException",
    );
    ok(call(
        &app,
        &admin,
        "CreateStream",
        json!({ "StreamName": "events", "StreamModeDetails": { "StreamMode": "ON_DEMAND" } }),
    )
    .await);

    let summary = ok(call(
        &app,
        &admin,
        "DescribeStreamSummary",
        json!({ "StreamName": "orders" }),
    )
    .await);
    let summary = &summary["StreamDescriptionSummary"];
    assert_eq!(summary["OpenShardCount"], 3);
    assert_eq!(summary["RetentionPeriodHours"], 24);
    assert_eq!(summary["StreamStatus"], "ACTIVE");
    let arn = summary["StreamARN"].as_str().unwrap().to_owned();
    assert!(arn.starts_with("arn:aws:kinesis:us-east-1:") && arn.ends_with(":stream/orders"));
    // By its ARN too.
    ok(call(&app, &admin, "DescribeStream", json!({ "StreamARN": arn })).await);

    let listed = ok(call(&app, &admin, "ListStreams", json!({ "Limit": 1 })).await);
    assert_eq!(listed["StreamNames"], json!(["events"]));
    assert_eq!(listed["HasMoreStreams"], true);
    let rest = ok(call(
        &app,
        &admin,
        "ListStreams",
        json!({ "NextToken": listed["NextToken"] }),
    )
    .await);
    assert_eq!(rest["StreamNames"], json!(["orders"]));
    assert_eq!(rest["HasMoreStreams"], false);

    let shards = ok(call(
        &app,
        &admin,
        "ListShards",
        json!({ "StreamName": "orders", "MaxResults": 2 }),
    )
    .await);
    assert_eq!(shards["Shards"].as_array().unwrap().len(), 2);
    assert_eq!(shards["Shards"][0]["ShardId"], "shardId-000000000000");
    assert_eq!(shards["Shards"][0]["HashKeyRange"]["StartingHashKey"], "0");
    let more = ok(call(
        &app,
        &admin,
        "ListShards",
        json!({ "NextToken": shards["NextToken"] }),
    )
    .await);
    assert_eq!(more["Shards"].as_array().unwrap().len(), 1);
    assert_eq!(
        more["Shards"][0]["HashKeyRange"]["EndingHashKey"],
        u128::MAX.to_string()
    );
    assert!(more.get("NextToken").is_none());

    let retention = |hours: u64| json!({ "StreamName": "orders", "RetentionPeriodHours": hours });
    ok(call(&app, &admin, "IncreaseStreamRetentionPeriod", retention(48)).await);
    refused(
        call(&app, &admin, "IncreaseStreamRetentionPeriod", retention(24)).await,
        "InvalidArgumentException",
    );
    refused(
        call(&app, &admin, "DecreaseStreamRetentionPeriod", retention(12)).await,
        "InvalidArgumentException",
    );
    ok(call(&app, &admin, "DecreaseStreamRetentionPeriod", retention(30)).await);
    let summary = ok(call(
        &app,
        &admin,
        "DescribeStreamSummary",
        json!({ "StreamName": "orders" }),
    )
    .await);
    assert_eq!(
        summary["StreamDescriptionSummary"]["RetentionPeriodHours"],
        30
    );

    refused(
        call(
            &app,
            &nobody,
            "DeleteStream",
            json!({ "StreamName": "orders" }),
        )
        .await,
        "AccessDeniedException",
    );
    ok(call(
        &app,
        &admin,
        "DeleteStream",
        json!({ "StreamName": "orders" }),
    )
    .await);
    refused(
        call(
            &app,
            &admin,
            "DeleteStream",
            json!({ "StreamName": "orders" }),
        )
        .await,
        "ResourceNotFoundException",
    );
    refused(
        call(
            &app,
            &admin,
            "DescribeStream",
            json!({ "StreamName": "orders" }),
        )
        .await,
        "ResourceNotFoundException",
    );
}

/// Records are numbered per shard from 0, a partition key's all in one
/// shard, and read back in order: from the oldest, from a sequence number
/// (at or after it), from the latest, a few at a time.
#[tokio::test]
async fn records_are_read_back_in_order() {
    let Some((app, admin, nobody)) = node().await else {
        return;
    };
    ok(call(
        &app,
        &admin,
        "CreateStream",
        json!({ "StreamName": "s", "ShardCount": 2 }),
    )
    .await);

    // One key's records: one shard, numbered in the order they're written.
    let mut sequences = Vec::new();
    let mut key_shard = None;
    for i in 0..5u8 {
        let (shard, sequence) = put(&app, &admin, "s", "k", &[i]).await;
        assert!(key_shard.get_or_insert(shard.clone()) == &shard);
        sequences.push(sequence);
    }
    assert_eq!(sequences, (0..5).collect::<Vec<_>>());
    let key_shard = key_shard.unwrap();

    // A batch, spread over both shards by key; its answer in its order.
    let records: Vec<Value> = (0..100)
        .map(|i| json!({ "PartitionKey": format!("key-{i}"), "Data": STANDARD.encode(format!("r{i}")) }))
        .collect();
    let answer = ok(call(
        &app,
        &admin,
        "PutRecords",
        json!({ "StreamName": "s", "Records": records }),
    )
    .await);
    assert_eq!(answer["FailedRecordCount"], 0);
    let answered = answer["Records"].as_array().unwrap();
    assert_eq!(answered.len(), 100);
    let by_shard = |shard: &str| -> Vec<u64> {
        answered
            .iter()
            .filter(|r| r["ShardId"] == shard)
            .map(|r| r["SequenceNumber"].as_str().unwrap().parse().unwrap())
            .collect()
    };
    let zero = by_shard("shardId-000000000000");
    let one = by_shard("shardId-000000000001");
    assert!(
        !zero.is_empty() && !one.is_empty(),
        "the keys spread over both shards"
    );
    assert_eq!(zero.len() + one.len(), 100);
    // Within a shard, in the request's order, after the key's records if
    // they're in it.
    for (shard, numbers) in [
        ("shardId-000000000000", &zero),
        ("shardId-000000000001", &one),
    ] {
        let base = if shard == key_shard { 5 } else { 0 };
        assert_eq!(
            *numbers,
            (base..base + numbers.len() as u64).collect::<Vec<_>>()
        );
    }

    // Read back, a few at a time: every record, in order, as written.
    for shard in ["shardId-000000000000", "shardId-000000000001"] {
        let read = read_all(&app, &admin, "s", shard, 7).await;
        let numbers: Vec<u64> = read.iter().map(|r| r.0).collect();
        assert_eq!(numbers, (0..numbers.len() as u64).collect::<Vec<_>>());
        let mut expected = Vec::new();
        if shard == key_shard {
            expected.extend((0..5u8).map(|i| ("k".to_owned(), vec![i])));
        }
        for r in answered
            .iter()
            .enumerate()
            .filter(|(_, r)| r["ShardId"] == shard)
        {
            expected.push((format!("key-{}", r.0), format!("r{}", r.0).into_bytes()));
        }
        let got: Vec<(String, Vec<u8>)> = read.into_iter().map(|r| (r.1, r.2)).collect();
        assert_eq!(got, expected);
    }

    // At and after a sequence number.
    let iterator = |kind: &str, n: &str| json!({ "StreamName": "s", "ShardId": key_shard, "ShardIteratorType": kind, "StartingSequenceNumber": n });
    let at = ok(call(
        &app,
        &admin,
        "GetShardIterator",
        iterator("AT_SEQUENCE_NUMBER", "3"),
    )
    .await);
    let records = ok(call(
        &app,
        &admin,
        "GetRecords",
        json!({ "ShardIterator": at["ShardIterator"], "Limit": 1 }),
    )
    .await);
    assert_eq!(records["Records"][0]["SequenceNumber"], "3");
    let after = ok(call(
        &app,
        &admin,
        "GetShardIterator",
        iterator("AFTER_SEQUENCE_NUMBER", "3"),
    )
    .await);
    let records = ok(call(
        &app,
        &admin,
        "GetRecords",
        json!({ "ShardIterator": after["ShardIterator"], "Limit": 1 }),
    )
    .await);
    assert_eq!(records["Records"][0]["SequenceNumber"], "4");
    refused(
        call(
            &app,
            &admin,
            "GetShardIterator",
            iterator("AT_SEQUENCE_NUMBER", "100000"),
        )
        .await,
        "InvalidArgumentException",
    );

    // From the latest: nothing, until something is written.
    let latest = ok(call(
        &app,
        &admin,
        "GetShardIterator",
        json!({ "StreamName": "s", "ShardId": key_shard, "ShardIteratorType": "LATEST" }),
    )
    .await);
    let empty = ok(call(
        &app,
        &admin,
        "GetRecords",
        json!({ "ShardIterator": latest["ShardIterator"] }),
    )
    .await);
    assert_eq!(empty["Records"], json!([]));
    let (_, sequence) = put(&app, &admin, "s", "k", b"new").await;
    let new = ok(call(
        &app,
        &admin,
        "GetRecords",
        json!({ "ShardIterator": empty["NextShardIterator"] }),
    )
    .await);
    assert_eq!(new["Records"].as_array().unwrap().len(), 1);
    assert_eq!(new["Records"][0]["SequenceNumber"], sequence.to_string());
    assert_eq!(new["Records"][0]["Data"], STANDARD.encode("new"));

    // Reading takes kinesis:GetRecords.
    refused(
        call(
            &app,
            &nobody,
            "GetRecords",
            json!({ "ShardIterator": latest["ShardIterator"] }),
        )
        .await,
        "AccessDeniedException",
    );
    // A record's data is at most 1 MiB.
    refused(
        call(
            &app,
            &admin,
            "PutRecord",
            json!({ "StreamName": "s", "PartitionKey": "k", "Data": STANDARD.encode(vec![0u8; super::MAX_DATA + 1]) }),
        )
        .await,
        "InvalidArgumentException",
    );
    // A missing stream.
    refused(
        call(
            &app,
            &admin,
            "PutRecord",
            json!({ "StreamName": "nope", "PartitionKey": "k", "Data": "" }),
        )
        .await,
        "ResourceNotFoundException",
    );
}

/// Many writers at once, to one shard: flushed together, numbered without
/// gaps or repeats, and read back in the order of their numbers.
#[tokio::test]
async fn concurrent_writes_are_numbered_without_gaps() {
    let Some((app, admin, _)) = node().await else {
        return;
    };
    ok(call(
        &app,
        &admin,
        "CreateStream",
        json!({ "StreamName": "c", "ShardCount": 1 }),
    )
    .await);
    let mut writers = tokio::task::JoinSet::new();
    for i in 0..64u32 {
        let app = app.clone();
        let admin = admin.clone();
        writers.spawn(async move {
            let (_, sequence) = put(&app, &admin, "c", &format!("w{i}"), &i.to_le_bytes()).await;
            (sequence, i)
        });
    }
    let written: Vec<(u64, u32)> = writers.join_all().await;
    let numbers: BTreeSet<u64> = written.iter().map(|w| w.0).collect();
    assert_eq!(numbers, (0..64).collect());
    let read = read_all(&app, &admin, "c", "shardId-000000000000", 10_000).await;
    assert_eq!(read.len(), 64);
    for (sequence, key, data) in read {
        let i = u32::from_le_bytes(data.try_into().unwrap());
        assert_eq!(key, format!("w{i}"));
        assert!(written.contains(&(sequence, i)));
    }
    // Fewer objects than records: writes were flushed together.
    let objects = crate::e2e::query_i64(
        &app,
        "SELECT count(DISTINCT object_key) FROM stream_batches",
    )
    .await;
    assert!(objects < 64, "{objects} objects for 64 records");
}

/// Records past their stream's retention are dropped from its index, and
/// the objects no record is in any more are deleted, those of a deleted
/// stream's too.
#[tokio::test]
async fn expired_and_deleted_records_are_cleaned_up() {
    let Some((app, admin, _)) = node().await else {
        return;
    };
    for name in ["old", "gone", "kept"] {
        ok(call(
            &app,
            &admin,
            "CreateStream",
            json!({ "StreamName": name, "ShardCount": 1 }),
        )
        .await);
        put(&app, &admin, name, "k", name.as_bytes()).await;
    }
    let objects = || {
        crate::e2e::query_i64(
            &app,
            "SELECT count(*) FROM objects WHERE bucket = 'cairn_internal' AND key LIKE 'streams/%' AND is_latest",
        )
    };
    assert!(objects().await >= 1);
    // "old"'s record is past its retention; "gone" is deleted.
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE stream_batches b SET arrived_at = now() - interval '25 hours'
             FROM streams s WHERE s.id = b.stream_id AND s.name = 'old'",
            &[],
        )
        .await
        .unwrap();
    ok(call(
        &app,
        &admin,
        "DeleteStream",
        json!({ "StreamName": "gone" }),
    )
    .await);
    // As if the objects were written long ago: orphans are only deleted
    // once they're older than a flush can take.
    client
        .execute(
            "UPDATE objects SET last_modified = now() - interval '1 hour'
             WHERE bucket = 'cairn_internal' AND key LIKE 'streams/%'",
            &[],
        )
        .await
        .unwrap();
    drop(client);
    super::sweep(&app).await.unwrap();
    assert!(
        read_all(&app, &admin, "old", "shardId-000000000000", 100)
            .await
            .is_empty()
    );
    let kept = read_all(&app, &admin, "kept", "shardId-000000000000", 100).await;
    assert_eq!(kept, vec![(0, "k".to_owned(), b"kept".to_vec())]);
    // Only the objects "kept"'s record is in are left.
    let left = crate::e2e::query_i64(
        &app,
        "SELECT count(DISTINCT object_key) FROM stream_batches",
    )
    .await;
    assert_eq!(objects().await, left);
    // Without it, none.
    ok(call(
        &app,
        &admin,
        "DeleteStream",
        json!({ "StreamName": "kept" }),
    )
    .await);
    super::sweep(&app).await.unwrap();
    assert_eq!(objects().await, 0);
}
