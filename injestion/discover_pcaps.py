import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List

from registry import EvidenceRegistry


SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".zip"}


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def discover_files(root: Path) -> Iterator[Path]:
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            file_path = Path(dirpath) / filename
            if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield file_path.resolve()


def determine_file_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pcap":
        return "pcap"
    if suffix == ".pcapng":
        return "pcapng"
    if suffix == ".zip":
        return "zip"
    return "unknown"


def determine_source_group(root: Path, file_path: Path) -> str:
    try:
        rel = file_path.relative_to(root.resolve())
        parts = rel.parts
        if len(parts) >= 2:
            return parts[0]
        return "root"
    except Exception:
        return "unknown"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_record(
    registry: EvidenceRegistry,
    root: Path,
    file_path: Path
) -> Dict:
    file_hash = sha256_file(file_path)
    size_bytes = file_path.stat().st_size
    file_type = determine_file_type(file_path)
    source_group = determine_source_group(root, file_path)
    discovered_at = utc_now_iso()

    existing_same_hash = registry.get_existing_by_hash(file_hash)

    if file_type == "zip":
        ingest_status = "ARCHIVE_PENDING"
        notes = "Archive discovered; unpacking handled in later stage."
    elif existing_same_hash is not None:
        ingest_status = "DUPLICATE"
        notes = f"Duplicate of {existing_same_hash['pcap_id']} based on SHA256."
    else:
        ingest_status = "NEW"
        notes = ""

    return {
        "pcap_id": registry.generate_pcap_id(),
        "filename": file_path.name,
        "full_path": str(file_path),
        "sha256": file_hash,
        "size_bytes": size_bytes,
        "file_type": file_type,
        "source_group": source_group,
        "discovered_at": discovered_at,
        "ingest_status": ingest_status,
        "notes": notes
    }


def scan_and_register(root_dir: str, db_path: str, export_json: str = "") -> None:
    root = Path(root_dir).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Input directory does not exist: {root}")

    registry = EvidenceRegistry(db_path=db_path)
    discovered_records: List[Dict] = []
    skipped_existing_paths = 0

    try:
        for file_path in discover_files(root):
            existing_by_path = registry.get_existing_by_path(str(file_path))
            if existing_by_path is not None:
                skipped_existing_paths += 1
                print(f"[SKIP] Already registered: {file_path}")
                continue

            try:
                record = build_record(registry, root, file_path)
                registry.insert_record(record)
                discovered_records.append(record)
                print(
                    f"[OK] Registered {record['pcap_id']} | "
                    f"{record['ingest_status']} | {file_path}"
                )
            except Exception as e:
                print(f"[ERROR] Failed to register {file_path}: {e}")

        summary = registry.fetch_summary()
        print("\n=== REGISTRY SUMMARY ===")
        for status, count in sorted(summary.items()):
            print(f"{status}: {count}")
        print(f"Already registered and skipped: {skipped_existing_paths}")

        if export_json:
            export_path = Path(export_json).resolve()
            export_path.parent.mkdir(parents=True, exist_ok=True)

            rows = registry.fetch_all()
            export_data = [dict(row) for row in rows]

            with export_path.open("w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)

            print(f"\n[OK] Exported registry snapshot to: {export_path}")

    finally:
        registry.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Discover PCAP/PCAPNG/ZIP files and register them in SQLite."
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        help="Root directory to scan recursively."
    )
    parser.add_argument(
        "--db-path",
        default="evidence_registry.db",
        help="Path to SQLite registry database."
    )
    parser.add_argument(
        "--export-json",
        default="",
        help="Optional path to export full registry as JSON."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    scan_and_register(
        root_dir=args.input_dir,
        db_path=args.db_path,
        export_json=args.export_json
    )