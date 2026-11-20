//! Base snapshots of the database, built a chunk at a time.
//!
//! A base of a large cluster is hundreds of GiB, which takes hours to write.
//! So it isn't taken in one transaction, but in chunks of about
//! [`CHUNK_BYTES`] (before compression), each read in a short transaction of its
//! own: the tables in order, each in slices of its key. After every chunk,
//! the runner records where it got to (`backup_state.building`), so a base
//! that's interrupted (the node dies, the target goes away) carries on from
//! its last chunk, on whichever node runs the backup next. And between
//! chunks, a step of the runner ships journals as usual, so a base being
//! built doesn't hold the RPO up.
//!
//! Its chunks are of different moments, which a restore reconciles: every
//! slice records the snapshot it was read in, and the journals from the
//! base's beginning are replayed but for the changes a row's slice holds
//! already (see `restore`). That's consistent once the replay reaches a
//! moment after the last chunk: the base is restorable only with a journal
//! after it was complete (`ready_after`).
//!
//! The manifest is written last: a base without one is incomplete, and a
//! restore ignores it. Until a base is complete, the one before stays the
//! one to restore from.

use std::time::{Duration, Instant};

use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use super::crypt::ObjectWriter;
use super::cycle::{Runner, now_millis};
use super::format::{self, BaseManifest, Building, ChunkHeader, ChunkRef, Section};
use super::{State, capture};

/// About how many bytes a chunk holds, before it's compressed.
#[cfg(not(test))]
const CHUNK_BYTES: usize = 256 << 20;
#[cfg(test)]
const CHUNK_BYTES: usize = 4 << 10;
/// How many rows a slice of a table holds at most.
#[cfg(not(test))]
const SLICE_ROWS: i64 = 100_000;
#[cfg(test)]
const SLICE_ROWS: i64 = 20;
/// How long a step builds a base at most (after one chunk at least), before
/// it ships journals again.
#[cfg(not(test))]
pub const BUDGET: Duration = Duration::from_secs(60);
#[cfg(test)]
pub const BUDGET: Duration = Duration::ZERO;

impl Runner<'_> {
    /// Begins a base: the tables it's to hold, as of now.
    pub async fn start_base(&mut self, state: &State, version: i32) -> anyhow::Result<()> {
        let client = self.app.pool.get().await?;
        let mut tables: Vec<String> = capture::tables(&client)
            .await?
            .into_iter()
            .map(|t| t.name)
            .collect();
        tables.push(format::OBJECTS.to_owned());
        tables.push(format::PARTS.to_owned());
        drop(client);
        let building = Building {
            id: Uuid::now_v7(),
            after: state.journal_seq,
            after_id: state.journal_id,
            version,
            tables,
            table: 0,
            cursor: None,
            chunks: Vec::new(),
            bytes: 0,
        };
        self.record(
            &building,
            "requested = CASE WHEN requested = 'base' THEN NULL ELSE requested END",
        )
        .await
    }

    /// Gives up a base being built (the schema changed under it): its chunks
    /// are deleted, as garbage.
    pub async fn abandon_base(&mut self) -> anyhow::Result<()> {
        let mut client = self.app.pool.get().await?;
        let tx = client.transaction().await?;
        self.check_generation(&tx).await?;
        tx.execute("UPDATE backup_state SET building = NULL", &[])
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Records a base's progress, and whatever else `set` says, if this
    /// runner is still the backup's.
    async fn record(&mut self, building: &Building, set: &str) -> anyhow::Result<()> {
        let text = serde_json::to_string(building)?;
        let mut client = self.app.pool.get().await?;
        let tx = client.transaction().await?;
        self.check_generation(&tx).await?;
        tx.execute(
            &format!("UPDATE backup_state SET building = $1, {set}"),
            &[&text],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Builds the base begun, a chunk at a time, for about `budget`. Its
    /// size, if it's complete.
    pub async fn build_base(
        &mut self,
        state: &State,
        budget: Duration,
    ) -> anyhow::Result<Option<u64>> {
        let mut building = state.building.clone().expect("a base being built");
        let began = Instant::now();
        loop {
            if building.table >= building.tables.len() {
                return self.complete_base(building).await.map(Some);
            }
            let chunk = self.write_chunk(&mut building).await?;
            building.bytes += chunk;
            self.record(&building, "lease_until = lease_until").await?;
            if began.elapsed() >= budget {
                return Ok(None);
            }
        }
    }

    /// Writes the next chunk of a base, and moves `building` past it; the
    /// chunk's size.
    async fn write_chunk(&self, building: &mut Building) -> anyhow::Result<u64> {
        let dir = format::base_dir(building.after, building.id);
        let id = Uuid::now_v7();
        let name = format::chunk_name(&dir, building.chunks.len(), id);
        // Garbage until the base is complete (and the sweep spares the
        // chunks of the base being built).
        self.app
            .pool
            .get()
            .await?
            .execute(
                "INSERT INTO backup_objects (id, name, kind, seq, size, superseded_at, base)
                 VALUES ($1, $2, 'base', $3, 0, now(), $4)",
                &[&id, &name, &building.after, &building.id],
            )
            .await?;
        let mut writer = ObjectWriter::new(&self.target, &self.key, &name);
        let mut next = building.clone();
        match self.fill_chunk(&mut next, &mut writer).await {
            Ok((snapshot, sections)) => {
                let size = writer.finish().await?;
                self.app
                    .pool
                    .get()
                    .await?
                    .execute(
                        "UPDATE backup_objects SET size = $2 WHERE id = $1",
                        &[&id, &(size as i64)],
                    )
                    .await?;
                next.chunks.push(ChunkRef {
                    name,
                    snapshot,
                    sections,
                });
                *building = next;
                Ok(size)
            }
            Err(e) => {
                writer.abort().await;
                Err(e)
            }
        }
    }

    /// Reads the slices of the next chunk, in a transaction of its own, into
    /// `writer`, moving `building` past them.
    async fn fill_chunk(
        &self,
        building: &mut Building,
        writer: &mut ObjectWriter,
    ) -> anyhow::Result<(String, Vec<Section>)> {
        use futures_util::StreamExt;
        use std::pin::pin;
        let mut client = self.app.pool.get().await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        tx.batch_execute("SET LOCAL DateStyle = 'ISO, YMD'; SET LOCAL TimeZone = 'UTC'; SET LOCAL extra_float_digits = 3;")
            .await?;
        let snapshot: String = tx
            .query_one("SELECT pg_current_snapshot()::text", &[])
            .await?
            .get(0);
        let version: i32 = tx
            .query_one("SELECT max(version) FROM schema_migrations", &[])
            .await?
            .get(0);
        anyhow::ensure!(
            version == building.version,
            "the schema changed while a base was built"
        );
        let tables = capture::tables(&tx).await?;
        let mut gzip = format::Gzip::new();
        let mut written = 0;
        let header = ChunkHeader {
            format: format::FORMAT,
            snapshot: snapshot.clone(),
        };
        let mut line = serde_json::to_vec(&header)?;
        line.push(b'\n');
        writer.write(&gzip.write(&line)?).await?;
        let mut sections = Vec::new();
        while building.table < building.tables.len() && written < CHUNK_BYTES {
            let name = building.tables[building.table].clone();
            // What to read of it: its columns, and its key, if it's read in
            // slices of it.
            let table = match name.as_str() {
                format::OBJECTS => capture::Table {
                    name: "backup_objects".into(),
                    columns: vec![
                        ("id".into(), false),
                        ("name".into(), false),
                        ("size".into(), false),
                    ],
                    identity: false,
                    types: vec!["uuid".into(), "text".into(), "bigint".into()],
                    key: None,
                },
                format::PARTS => capture::Table {
                    name: "backup_parts".into(),
                    columns: ["part_id", "object", "offset", "size", "class"]
                        .iter()
                        .map(|c| (c.to_string(), false))
                        .collect(),
                    identity: false,
                    types: ["bigint", "uuid", "bigint", "bigint", "text"]
                        .iter()
                        .map(|t| t.to_string())
                        .collect(),
                    key: Some(vec!["part_id".into()]),
                },
                _ => match tables.iter().find(|t| t.name == name) {
                    Some(table) => table.clone(),
                    None => {
                        // Dropped since the base began (a schema change
                        // would have abandoned it): nothing to hold.
                        building.table += 1;
                        building.cursor = None;
                        continue;
                    }
                },
            };
            let columns: Vec<String> = table
                .columns
                .iter()
                .filter(|(_, generated)| !generated)
                .map(|(c, _)| c.clone())
                .collect();
            let t = capture::quote(&table.name);
            let mut filter = String::from("true");
            if name == format::OBJECTS {
                filter = "kind <> 'base'".into();
            }
            let mut upper: Option<String> = None;
            let mut order = String::new();
            if let Some(key) = &table.key {
                let row = table.key_row("x");
                let after = match &building.cursor {
                    Some(cursor) => {
                        format!(
                            "{row} > {}",
                            table.key_of(&format!("'{}'::jsonb", cursor.replace('\'', "''")))
                        )
                    }
                    None => "true".into(),
                };
                let key_cols = key
                    .iter()
                    .map(|c| format!("x.{}", capture::quote(c)))
                    .collect::<Vec<_>>();
                order = format!("ORDER BY {}", key_cols.join(", "));
                upper = tx
                    .query_opt(
                        &format!(
                            "SELECT jsonb_build_array({})::text FROM {t} x WHERE {after} {order} OFFSET $1 LIMIT 1",
                            key_cols.join(", ")
                        ),
                        &[&(SLICE_ROWS - 1)],
                    )
                    .await?
                    .map(|r| r.get(0));
                filter = match &upper {
                    Some(upper) => format!(
                        "{after} AND {row} <= {}",
                        table.key_of(&format!("'{}'::jsonb", upper.replace('\'', "''")))
                    ),
                    None => after,
                };
            }
            let cols = columns
                .iter()
                .map(|c| format!("x.{}", capture::quote(c)))
                .collect::<Vec<_>>()
                .join(", ");
            let copy = format!("COPY (SELECT {cols} FROM {t} x WHERE {filter} {order}) TO STDOUT");
            let section = Section {
                table: name.clone(),
                columns,
                upper: upper.clone(),
            };
            let mut line = serde_json::to_vec(&section)?;
            line.push(b'\n');
            writer.write(&gzip.write(&line)?).await?;
            let mut stream = pin!(tx.copy_out(copy.as_str()).await?);
            while let Some(data) = stream.next().await {
                let data = data?;
                written += data.len();
                let out = gzip.write(&data)?;
                if !out.is_empty() {
                    writer.write(&out).await?;
                }
            }
            writer.write(&gzip.write(b"\\.\n")?).await?;
            sections.push(section);
            match upper {
                Some(upper) => building.cursor = Some(upper),
                None => {
                    building.table += 1;
                    building.cursor = None;
                }
            }
        }
        tx.commit().await?;
        let mut out = gzip.write(b"end\n")?;
        out.extend(gzip.finish()?);
        writer.write(&out).await?;
        Ok((snapshot, sections))
    }

    /// Writes a complete base's manifest, and makes it the one to restore
    /// from, once a journal follows it.
    async fn complete_base(&mut self, building: Building) -> anyhow::Result<u64> {
        let client = self.app.pool.get().await?;
        let sequences = capture::sequences(&client).await?;
        let ready_after: i64 = client
            .query_one("SELECT journal_seq FROM backup_state", &[])
            .await?
            .get(0);
        let dir = format::base_dir(building.after, building.id);
        let name = format::manifest_name(&dir);
        let id = Uuid::now_v7();
        client
            .execute(
                "INSERT INTO backup_objects (id, name, kind, seq, size, superseded_at, base)
                 VALUES ($1, $2, 'base', $3, 0, now(), $4) ON CONFLICT (name) DO NOTHING",
                &[&id, &name, &building.after, &building.id],
            )
            .await?;
        drop(client);
        let manifest = BaseManifest {
            format: format::FORMAT,
            id: building.id,
            after: building.after,
            after_id: building.after_id,
            ready_after,
            version: building.version,
            time: now_millis(),
            sequences,
            chunks: building.chunks.clone(),
        };
        let mut writer = ObjectWriter::new(&self.target, &self.key, &name);
        writer.write(&format::seal_meta(&manifest)?).await?;
        writer.finish().await?;
        let names: Vec<String> = building
            .chunks
            .iter()
            .map(|c| c.name.clone())
            .chain(std::iter::once(name))
            .collect();
        let mut client = self.app.pool.get().await?;
        let tx = client.transaction().await?;
        self.check_generation(&tx).await?;
        // Its chunks are no garbage; those of attempts that failed are.
        tx.execute(
            "UPDATE backup_objects SET superseded_at = NULL WHERE base = $1 AND name = ANY($2)",
            &[&building.id, &names],
        )
        .await?;
        // A journal follows at once, which makes it restorable.
        tx.execute(
            "UPDATE backup_state SET building = NULL, base_seq = $1, base_ready_seq = $2, base_id = $3,
                 base_at = now(), base_version = $4, base_size = $5, journals_since_base = 0,
                 bytes_since_base = 0, requested = coalesce(requested, 'now')",
            &[&building.after, &ready_after, &building.id, &building.version, &(building.bytes as i64)],
        )
        .await?;
        tx.commit().await?;
        Ok(building.bytes)
    }
}
