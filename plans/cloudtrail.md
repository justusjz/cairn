# CloudTrail

An audit log, as AWS's CloudTrail keeps it: a record of each API call, in
CloudTrail's event format, which Cairn's own API for it (`LookupEvents`,
trails) answers and delivers. It starts with the KMS, whose users need it
most ("who decrypted with this key, and when"), and grows to IAM, STS and
S3's management calls.

## What AWS promises

Less than one might expect. From CloudTrail's user guide, as of November
2026:

- Delivery "typically within an average of about 5 minutes of an API call.
  This time is not guaranteed." The SLA covers the API's availability only
  (99.9%), nothing about events being recorded or delivered.
- Log files can hold duplicate events (with the same `eventID`), and
  aren't "an ordered stack trace": events are in no particular order.
- Configuration (trails, event selectors) is eventually consistent.
- A trail whose bucket doesn't take its files is retried for 30 days.
- Event history: 90 days of management events, `LookupEvents` with one
  attribute filter at a time, at 2 requests a second.

Nothing says an event is recorded atomically with what it records.

## The guarantees Cairn gives

More than that, without putting the database in the path of every event
(it's what's already most loaded):

1. **A call's record is durable before its call is answered.** Each node
   appends its records to a log in its data dir, and `fdatasync`s it,
   group-committed (one sync for every append waiting), before answering.
   The record is written once the call is done, with its outcome: every
   answer a client got has its record. A call that only reads (Decrypt)
   has its effect in its answer, so its record is there before its effect.
2. **A record that can't be logged fails its call** (a 500). Nothing that
   was answered passes unrecorded.
3. **Records reach the cluster's storage within five minutes**, as often
   as CloudTrail delivers. Each node's file is closed at each five-minute
   mark of the clock (if it logged anything), the same marks on every node,
   and shipped within seconds, gzipped, into the internal bucket,
   replicated as objects are. The database sees one object's metadata per
   file, not a row per event: 20 busy nodes write an object every 15
   seconds, about 520,000 in 90 days. A node's disk loss costs up to five
   minutes of its records.
4. **Nothing is dropped.** A file that fails to ship is kept and tried
   again for as long as it takes; each file is one object whose key is the
   file's name, so shipping one again writes over the same object.
5. **Records are kept 90 days** in the internal bucket (event history's).

Not covered: a change whose node crashes after making it and before its
record is synced (its client got no answer). Recording an intent first
would cover it, at the cost of a second record kind that readers would
have to show as "outcome unknown"; CloudTrail doesn't promise it either,
so Cairn doesn't.

Not promised, as CloudTrail doesn't: order across nodes, or exactly-once
delivery to trails (readers deduplicate by `eventID`).

## Phases

1. **The log, and KMS's events.** Done: `audit` (the event format,
   `userIdentity`), `audit::log` (the durable log), `audit::ship` (shipping
   and expiry), and every KMS API call recorded (`kms::api::audited`).
2. **`LookupEvents`**, over the internal bucket's objects (by their keys'
   hours), with its attribute filters and paging; a small index beside
   each object (event names, users, resources) so that a filter skips
   objects. And the console's view of them.
3. **Trails**: `CreateTrail`, `UpdateTrail`, `DeleteTrail`,
   `DescribeTrails`, `GetTrailStatus`, `StartLogging`/`StopLogging`,
   `Put`/`GetEventSelectors` (and advanced ones, at least `readOnly` and
   excluding KMS's events), tags. Delivery from the internal bucket to the
   trail's bucket, as CloudTrail's `{"Records":[...]}` files at
   `AWSLogs/<account>/CloudTrail/<region>/<y>/<m>/<d>/...json.gz`, about
   30 seconds after each five-minute mark, when every node has shipped
   the five minutes before (a file that misses it, a node's slow or down,
   goes with the next): so an event is delivered within about 5.5
   minutes, under 3 on average, rather than within 10, as two unaligned
   five-minute steps would make it; at least once, a cursor per trail and node; retried
   for 30 days, its last error in `GetTrailStatus`. One node at a time
   delivers (a lease), reading the shipped objects, not other nodes'
   disks, so a node that's down doesn't hold the others' records up. The trail's bucket's
   policy must let `cloudtrail.amazonaws.com` write, as in AWS.
4. **Digest files** (log file integrity validation): hourly, signed, each
   naming the one before; `ListPublicKeys`, so that `aws cloudtrail
   validate-logs` works.
5. **More events**: IAM's, STS's, S3's management calls, the console's
   (as the user, so the console is no way around the log), and calls Cairn
   makes for someone (SSE-KMS's to the KMS, with `invokedBy`). For
   SSE-KMS, to be decided: an event per object (AWS's without S3 Bucket
   Keys) or per data key and period (with them); per object makes GETs of
   SSE-KMS objects cost a record each.

Not planned: CloudTrail Lake, CloudWatch Logs, Insights.

## Open questions

- Cross-account use of a key: AWS records the event in both the caller's
  and the key owner's accounts (`sharedEventID`). Phase 1 records it once,
  for the caller's.
- Calls refused before they're authenticated (an unknown key, a bad
  signature) aren't recorded; AWS records some of them.
