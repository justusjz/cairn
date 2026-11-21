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
2. **A call that may change something logs its intent first.** Before it
   does anything; its event, with its outcome, after. An intent without its
   event (the node crashed between) says the call may have taken effect.
   A call that only reads (Decrypt) has its effect in its answer, so its
   event, logged before the answer, is logged before the effect.
3. **A record that can't be logged fails its call** (a 500), before the
   call does anything, for an intent. Nothing passes unrecorded.
4. **Records reach the cluster's storage within seconds.** Each node's
   files are closed every 5 seconds and shipped (gzipped) into the internal
   bucket, replicated as objects are. The database sees one object's
   metadata per file, not a row per event. The window a node's disk loss
   costs is those few seconds.
5. **Nothing is dropped.** A file that fails to ship is kept and tried
   again for as long as it takes; each file is one object whose key is the
   file's name, so shipping one again writes over the same object.
6. **Records are kept 90 days** in the internal bucket (event history's).

Not promised, as CloudTrail doesn't: order across nodes, or exactly-once
delivery to trails (readers deduplicate by `eventID`).

## Phases

1. **The log, and KMS's events.** Done: `audit` (the event format,
   `userIdentity`), `audit::log` (the durable log), `audit::ship` (shipping
   and expiry), and every KMS API call recorded (`kms::api::audited`).
2. **`LookupEvents`**, over the internal bucket's objects (by their keys'
   hours), with its attribute filters and paging; a small index beside
   each object (event names, users, resources) so that a filter skips
   objects. Intents without events (see `audit::settle`) are shown as
   events whose outcome is unknown. And the console's view of them.
3. **Trails**: `CreateTrail`, `UpdateTrail`, `DeleteTrail`,
   `DescribeTrails`, `GetTrailStatus`, `StartLogging`/`StopLogging`,
   `Put`/`GetEventSelectors` (and advanced ones, at least `readOnly` and
   excluding KMS's events), tags. Delivery from the internal bucket to the
   trail's bucket, as CloudTrail's `{"Records":[...]}` files at
   `AWSLogs/<account>/CloudTrail/<region>/<y>/<m>/<d>/...json.gz`, about
   every 5 minutes, at least once, a cursor per trail and node; retried
   for 30 days, its last error in `GetTrailStatus`. The trail's bucket's
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
