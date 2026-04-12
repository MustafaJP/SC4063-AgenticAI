import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, List


class EvidenceRegistry:
    def __init__(self, db_path: str = "evidence_registry.db") -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
        self._ensure_step2_columns()
        self._ensure_step3_tables()
        self._ensure_step4_tables()
        self._ensure_step5_tables()
        self._ensure_step6_tables()
        self._ensure_step7_tables()
        self._ensure_step8_tables()


    def _init_db(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence_registry (
            pcap_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            full_path TEXT NOT NULL UNIQUE,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            file_type TEXT NOT NULL,
            source_group TEXT,
            discovered_at TEXT NOT NULL,
            ingest_status TEXT NOT NULL,
            notes TEXT
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_evidence_sha256
        ON evidence_registry (sha256)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_evidence_status
        ON evidence_registry (ingest_status)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_evidence_source_group
        ON evidence_registry (source_group)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS registry_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)

        self.conn.commit()

    def _ensure_step2_columns(self) -> None:
        cur = self.conn.cursor()
        cur.execute("PRAGMA table_info(evidence_registry)")
        existing_cols = {row["name"] for row in cur.fetchall()}

        required_columns = {
            "capture_first_packet_time": "TEXT",
            "capture_last_packet_time": "TEXT",
            "capture_duration_seconds": "REAL",
            "capture_packet_count": "INTEGER",
            "capture_data_size_bytes": "INTEGER",
            "capture_file_size_bytes": "INTEGER",
            "capture_encapsulation": "TEXT",
            "metadata_extracted_at": "TEXT",
            "metadata_tool": "TEXT",
            "metadata_status": "TEXT",
        }

        for col_name, col_type in required_columns.items():
            if col_name not in existing_cols:
                cur.execute(
                    f"ALTER TABLE evidence_registry ADD COLUMN {col_name} {col_type}"
                )

        self.conn.commit()

    def _ensure_step3_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS pcap_overlap_map (
            overlap_id INTEGER PRIMARY KEY AUTOINCREMENT,
            pcap_id_1 TEXT NOT NULL,
            pcap_id_2 TEXT NOT NULL,
            start_1 TEXT,
            end_1 TEXT,
            start_2 TEXT,
            end_2 TEXT,
            overlap_seconds REAL,
            overlap_ratio_1 REAL,
            overlap_ratio_2 REAL,
            relation_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(pcap_id_1, pcap_id_2)
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_overlap_pcap1
        ON pcap_overlap_map (pcap_id_1)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_overlap_pcap2
        ON pcap_overlap_map (pcap_id_2)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS pcap_processing_plan (
            pcap_id TEXT PRIMARY KEY,
            time_bucket TEXT,
            overlap_class TEXT NOT NULL,
            processing_priority INTEGER NOT NULL,
            parse_group TEXT,
            planner_notes TEXT,
            created_at TEXT NOT NULL
        )
        """)

        self.conn.commit()
    
    def _ensure_step4_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS pcap_chunk_plan (
            chunk_id TEXT PRIMARY KEY,
            pcap_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            chunk_start_offset_seconds REAL NOT NULL,
            chunk_end_offset_seconds REAL NOT NULL,
            estimated_packets INTEGER,
            estimated_bytes INTEGER,
            chunk_strategy TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_chunk_plan_pcap
        ON pcap_chunk_plan (pcap_id)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS extraction_task_plan (
            task_id TEXT PRIMARY KEY,
            pcap_id TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            task_type TEXT NOT NULL,
            task_priority INTEGER NOT NULL,
            task_status TEXT NOT NULL,
            planner_notes TEXT,
            created_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_task_plan_pcap
        ON extraction_task_plan (pcap_id)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_task_plan_chunk
        ON extraction_task_plan (chunk_id)
        """)

        self.conn.commit()

    def clear_step4_tables(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM extraction_task_plan")
        cur.execute("DELETE FROM pcap_chunk_plan")
        self.conn.commit()

    def _ensure_step5_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS normalized_events (
            event_id TEXT PRIMARY KEY,
            pcap_id TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            network_proto TEXT,
            app_proto TEXT,
            summary TEXT,
            raw_json TEXT,
            created_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_events_pcap
        ON normalized_events (pcap_id)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_events_chunk
        ON normalized_events (chunk_id)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_events_task
        ON normalized_events (task_id)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS extraction_task_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            pcap_id TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            task_type TEXT NOT NULL,
            run_started_at TEXT NOT NULL,
            run_finished_at TEXT,
            run_status TEXT NOT NULL,
            records_written INTEGER,
            error_message TEXT
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_task_runs_task
        ON extraction_task_runs (task_id)
        """)

        self.conn.commit()

    def _ensure_step6_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_handoff_bundles (
            bundle_id TEXT PRIMARY KEY,
            time_bucket TEXT,
            parse_group TEXT NOT NULL,
            bundle_path TEXT NOT NULL,
            pcap_count INTEGER NOT NULL,
            event_count INTEGER NOT NULL,
            bundle_status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_ai_bundles_group
        ON ai_handoff_bundles (parse_group)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_ai_bundles_bucket
        ON ai_handoff_bundles (time_bucket)
        """)

        self.conn.commit()


    def clear_step6_tables(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM ai_handoff_bundles")
        self.conn.commit()

    def _ensure_step7_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_bundle_summaries (
            bundle_id TEXT PRIMARY KEY,
            parse_group TEXT NOT NULL,
            summary_path TEXT NOT NULL,
            retrieval_path TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            summary_status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_ai_bundle_summaries_group
        ON ai_bundle_summaries (parse_group)
        """)

        self.conn.commit()


    def clear_step7_tables(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM ai_bundle_summaries")
        self.conn.commit()

    def _ensure_step8_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_query_audit (
            query_id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_type TEXT NOT NULL,
            query_text TEXT,
            bundle_id TEXT,
            filters_json TEXT,
            result_count INTEGER,
            query_timestamp TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_agent_query_audit_bundle
        ON agent_query_audit (bundle_id)
        """)

        self.conn.commit()


    def insert_agent_query_audit(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT INTO agent_query_audit (
            query_type,
            query_text,
            bundle_id,
            filters_json,
            result_count,
            query_timestamp
        ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record["query_type"],
            record.get("query_text"),
            record.get("bundle_id"),
            record.get("filters_json"),
            record.get("result_count"),
            record["query_timestamp"]
        ))
        self.conn.commit()


    def fetch_agent_query_audit(self, limit: int = 50):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM agent_query_audit
        ORDER BY query_id DESC
        LIMIT ?
        """, (limit,))
        return cur.fetchall()


    def fetch_ready_bundles(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM ai_handoff_bundles
        WHERE bundle_status = 'READY'
        ORDER BY created_at ASC, bundle_id ASC
        """)
        return cur.fetchall()


    def insert_ai_bundle_summary(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO ai_bundle_summaries (
            bundle_id,
            parse_group,
            summary_path,
            retrieval_path,
            event_count,
            summary_status,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            record["bundle_id"],
            record["parse_group"],
            record["summary_path"],
            record["retrieval_path"],
            record["event_count"],
            record["summary_status"],
            record["created_at"]
        ))
        self.conn.commit()


    def fetch_ai_bundle_summaries(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM ai_bundle_summaries
        ORDER BY created_at ASC, bundle_id ASC
        """)
        return cur.fetchall()


    def fetch_parse_groups(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT DISTINCT parse_group, time_bucket
        FROM pcap_processing_plan
        WHERE parse_group IS NOT NULL
        ORDER BY time_bucket ASC, parse_group ASC
        """)
        return cur.fetchall()


    def fetch_bundle_pcaps(self, parse_group: str):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT e.pcap_id,
            e.filename,
            e.full_path,
            e.sha256,
            e.capture_first_packet_time,
            e.capture_last_packet_time,
            e.capture_duration_seconds,
            e.capture_packet_count,
            e.capture_data_size_bytes,
            e.capture_file_size_bytes,
            e.capture_encapsulation,
            p.time_bucket,
            p.overlap_class,
            p.processing_priority,
            p.parse_group
        FROM evidence_registry e
        JOIN pcap_processing_plan p
        ON e.pcap_id = p.pcap_id
        WHERE p.parse_group = ?
        ORDER BY p.processing_priority ASC, e.capture_first_packet_time ASC
        """, (parse_group,))
        return cur.fetchall()


    def fetch_bundle_events(self, parse_group: str, limit: int = 5000):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT ne.*
        FROM normalized_events ne
        JOIN pcap_processing_plan pp
        ON ne.pcap_id = pp.pcap_id
        WHERE pp.parse_group = ?
        ORDER BY ne.event_timestamp ASC, ne.event_id ASC
        LIMIT ?
        """, (parse_group, limit))
        return cur.fetchall()


    def insert_ai_handoff_bundle(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO ai_handoff_bundles (
            bundle_id,
            time_bucket,
            parse_group,
            bundle_path,
            pcap_count,
            event_count,
            bundle_status,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["bundle_id"],
            record.get("time_bucket"),
            record["parse_group"],
            record["bundle_path"],
            record["pcap_count"],
            record["event_count"],
            record["bundle_status"],
            record["created_at"]
        ))
        self.conn.commit()


    def fetch_ai_handoff_bundles(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM ai_handoff_bundles
        ORDER BY created_at ASC, bundle_id ASC
        """)
        return cur.fetchall()


    def fetch_planned_tasks(self, limit: Optional[int] = None):
        cur = self.conn.cursor()

        query = """
        SELECT t.*, c.chunk_start_offset_seconds, c.chunk_end_offset_seconds,
            c.chunk_strategy, e.full_path, e.capture_first_packet_time,
            e.capture_last_packet_time
        FROM extraction_task_plan t
        JOIN pcap_chunk_plan c
        ON t.chunk_id = c.chunk_id
        JOIN evidence_registry e
        ON t.pcap_id = e.pcap_id
        WHERE t.task_status = 'PLANNED'
        ORDER BY t.task_priority ASC, t.task_id ASC
        """

        if limit is not None:
            query += "\nLIMIT ?"
            cur.execute(query, (limit,))
        else:
            cur.execute(query)

        return cur.fetchall()
    
    def fetch_planned_tasks_by_types(self, task_types: List[str], limit: Optional[int] = None):
        cur = self.conn.cursor()

        placeholders = ",".join("?" for _ in task_types)
        query = f"""
        SELECT t.*, c.chunk_start_offset_seconds, c.chunk_end_offset_seconds,
            c.chunk_strategy, e.full_path, e.capture_first_packet_time,
            e.capture_last_packet_time
        FROM extraction_task_plan t
        JOIN pcap_chunk_plan c
        ON t.chunk_id = c.chunk_id
        JOIN evidence_registry e
        ON t.pcap_id = e.pcap_id
        WHERE t.task_status = 'PLANNED'
        AND t.task_type IN ({placeholders})
        ORDER BY t.task_priority ASC, t.task_id ASC
        """
       
        params = list(task_types)

        if limit is not None:
            query += "\nLIMIT ?"
            params.append(limit)

        cur.execute(query, tuple(params))
        
        return cur.fetchall()


    def update_task_status(self, task_id: str, task_status: str) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        UPDATE extraction_task_plan
        SET task_status = ?
        WHERE task_id = ?
        """, (task_status, task_id))
        self.conn.commit()


    def insert_task_run(self, record: Dict[str, Any]) -> int:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT INTO extraction_task_runs (
            task_id,
            pcap_id,
            chunk_id,
            task_type,
            run_started_at,
            run_finished_at,
            run_status,
            records_written,
            error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["task_id"],
            record["pcap_id"],
            record["chunk_id"],
            record["task_type"],
            record["run_started_at"],
            record.get("run_finished_at"),
            record["run_status"],
            record.get("records_written"),
            record.get("error_message"),
        ))
        self.conn.commit()
        return cur.lastrowid


    def update_task_run(self, run_id: int, run_finished_at: str, run_status: str,
                        records_written: int = 0, error_message: str = "") -> None:
        cur = self.conn.cursor()
        cur.execute("""
        UPDATE extraction_task_runs
        SET run_finished_at = ?,
            run_status = ?,
            records_written = ?,
            error_message = ?
        WHERE run_id = ?
        """, (run_finished_at, run_status, records_written, error_message, run_id))
        self.conn.commit()


    def insert_normalized_event(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO normalized_events (
            event_id,
            pcap_id,
            chunk_id,
            task_id,
            event_type,
            event_timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            network_proto,
            app_proto,
            summary,
            raw_json,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["event_id"],
            record["pcap_id"],
            record["chunk_id"],
            record["task_id"],
            record["event_type"],
            record.get("event_timestamp"),
            record.get("src_ip"),
            record.get("dst_ip"),
            record.get("src_port"),
            record.get("dst_port"),
            record.get("network_proto"),
            record.get("app_proto"),
            record.get("summary"),
            record.get("raw_json"),
            record["created_at"]
        ))
        self.conn.commit()


    def fetch_normalized_events(self, limit: int = 100):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM normalized_events
        ORDER BY created_at ASC, event_id ASC
        LIMIT ?
        """, (limit,))
        return cur.fetchall()


    def fetch_task_runs(self, limit: int = 100):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM extraction_task_runs
        ORDER BY run_id DESC
        LIMIT ?
        """, (limit,))
        return cur.fetchall()


    def fetch_processing_plan_rows(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT e.*, p.time_bucket, p.overlap_class, p.processing_priority,
            p.parse_group, p.planner_notes
        FROM evidence_registry e
        JOIN pcap_processing_plan p
        ON e.pcap_id = p.pcap_id
        WHERE e.metadata_status = 'SUCCESS'
        ORDER BY p.processing_priority ASC, e.capture_first_packet_time ASC
        """)
        return cur.fetchall()


    def insert_chunk_plan(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO pcap_chunk_plan (
            chunk_id,
            pcap_id,
            chunk_index,
            chunk_start_offset_seconds,
            chunk_end_offset_seconds,
            estimated_packets,
            estimated_bytes,
            chunk_strategy,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["chunk_id"],
            record["pcap_id"],
            record["chunk_index"],
            record["chunk_start_offset_seconds"],
            record["chunk_end_offset_seconds"],
            record.get("estimated_packets"),
            record.get("estimated_bytes"),
            record["chunk_strategy"],
            record["created_at"]
        ))
        self.conn.commit()


    def insert_extraction_task(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO extraction_task_plan (
            task_id,
            pcap_id,
            chunk_id,
            task_type,
            task_priority,
            task_status,
            planner_notes,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["task_id"],
            record["pcap_id"],
            record["chunk_id"],
            record["task_type"],
            record["task_priority"],
            record["task_status"],
            record.get("planner_notes"),
            record["created_at"]
        ))
        self.conn.commit()

    def fetch_chunk_plan(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM pcap_chunk_plan
        ORDER BY pcap_id ASC, chunk_index ASC
        """)
        return cur.fetchall()


    def fetch_extraction_tasks(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM extraction_task_plan
        ORDER BY task_priority ASC, pcap_id ASC, chunk_id ASC, task_type ASC
        """)
        return cur.fetchall()

    def get_existing_by_path(self, full_path: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM evidence_registry WHERE full_path = ?",
            (full_path,)
        )
        return cur.fetchone()

    def get_existing_by_hash(self, sha256: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM evidence_registry WHERE sha256 = ? LIMIT 1",
            (sha256,)
        )
        return cur.fetchone()

    def _get_next_sequence(self) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT value FROM registry_metadata WHERE key = 'pcap_sequence'"
        )
        row = cur.fetchone()

        if row is None:
            seq = 1
            cur.execute(
                "INSERT INTO registry_metadata (key, value) VALUES ('pcap_sequence', ?)",
                (str(seq),)
            )
            self.conn.commit()
            return seq

        seq = int(row["value"]) + 1
        cur.execute(
            "UPDATE registry_metadata SET value = ? WHERE key = 'pcap_sequence'",
            (str(seq),)
        )
        self.conn.commit()
        return seq

    def generate_pcap_id(self) -> str:
        seq = self._get_next_sequence()
        return f"pcap_{seq:06d}"

    def insert_record(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT INTO evidence_registry (
            pcap_id,
            filename,
            full_path,
            sha256,
            size_bytes,
            file_type,
            source_group,
            discovered_at,
            ingest_status,
            notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["pcap_id"],
            record["filename"],
            record["full_path"],
            record["sha256"],
            record["size_bytes"],
            record["file_type"],
            record.get("source_group"),
            record["discovered_at"],
            record["ingest_status"],
            record.get("notes", "")
        ))
        self.conn.commit()

    def update_record_status(self, full_path: str, ingest_status: str, notes: str = "") -> None:
        cur = self.conn.cursor()
        cur.execute("""
        UPDATE evidence_registry
        SET ingest_status = ?, notes = ?
        WHERE full_path = ?
        """, (ingest_status, notes, full_path))
        self.conn.commit()

    def update_metadata(self, pcap_id: str, metadata: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        UPDATE evidence_registry
        SET
            capture_first_packet_time = ?,
            capture_last_packet_time = ?,
            capture_duration_seconds = ?,
            capture_packet_count = ?,
            capture_data_size_bytes = ?,
            capture_file_size_bytes = ?,
            capture_encapsulation = ?,
            metadata_extracted_at = ?,
            metadata_tool = ?,
            metadata_status = ?,
            ingest_status = ?,
            notes = ?
        WHERE pcap_id = ?
        """, (
            metadata.get("capture_first_packet_time"),
            metadata.get("capture_last_packet_time"),
            metadata.get("capture_duration_seconds"),
            metadata.get("capture_packet_count"),
            metadata.get("capture_data_size_bytes"),
            metadata.get("capture_file_size_bytes"),
            metadata.get("capture_encapsulation"),
            metadata.get("metadata_extracted_at"),
            metadata.get("metadata_tool"),
            metadata.get("metadata_status"),
            metadata.get("ingest_status"),
            metadata.get("notes", ""),
            pcap_id
        ))
        self.conn.commit()

    def fetch_all(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM evidence_registry
        ORDER BY discovered_at ASC, filename ASC
        """)
        return cur.fetchall()

    def fetch_summary(self) -> Dict[str, int]:
        cur = self.conn.cursor()
        cur.execute("""
        SELECT ingest_status, COUNT(*) AS count
        FROM evidence_registry
        GROUP BY ingest_status
        """)
        rows = cur.fetchall()
        return {row["ingest_status"]: row["count"] for row in rows}

    def fetch_for_metadata_extraction(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM evidence_registry
        WHERE file_type IN ('pcap', 'pcapng')
          AND ingest_status IN ('NEW', 'DUPLICATE')
        ORDER BY discovered_at ASC
        """)
        return cur.fetchall()

    def fetch_for_overlap_analysis(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM evidence_registry
        WHERE file_type IN ('pcap', 'pcapng')
          AND metadata_status = 'SUCCESS'
        ORDER BY capture_first_packet_time ASC
        """)
        return cur.fetchall()

    def clear_overlap_tables(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM pcap_overlap_map")
        cur.execute("DELETE FROM pcap_processing_plan")
        self.conn.commit()

    def insert_overlap_record(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO pcap_overlap_map (
            pcap_id_1,
            pcap_id_2,
            start_1,
            end_1,
            start_2,
            end_2,
            overlap_seconds,
            overlap_ratio_1,
            overlap_ratio_2,
            relation_type,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["pcap_id_1"],
            record["pcap_id_2"],
            record["start_1"],
            record["end_1"],
            record["start_2"],
            record["end_2"],
            record["overlap_seconds"],
            record["overlap_ratio_1"],
            record["overlap_ratio_2"],
            record["relation_type"],
            record["created_at"]
        ))
        self.conn.commit()

    def insert_processing_plan(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO pcap_processing_plan (
            pcap_id,
            time_bucket,
            overlap_class,
            processing_priority,
            parse_group,
            planner_notes,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            record["pcap_id"],
            record.get("time_bucket"),
            record["overlap_class"],
            record["processing_priority"],
            record.get("parse_group"),
            record.get("planner_notes"),
            record["created_at"]
        ))
        self.conn.commit()

    def fetch_overlap_map(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM pcap_overlap_map
        ORDER BY overlap_seconds DESC, pcap_id_1 ASC, pcap_id_2 ASC
        """)
        return cur.fetchall()

    def fetch_processing_plan(self):
        cur = self.conn.cursor()
        cur.execute("""
        SELECT *
        FROM pcap_processing_plan
        ORDER BY processing_priority ASC, pcap_id ASC
        """)
        return cur.fetchall()

    def close(self) -> None:
        self.conn.close()