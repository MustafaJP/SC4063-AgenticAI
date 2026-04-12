import argparse
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from registry import EvidenceRegistry


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_capinfos_output(output: str) -> Dict[str, Optional[object]]:
    metadata = {
        "capture_first_packet_time": None,
        "capture_last_packet_time": None,
        "capture_duration_seconds": None,
        "capture_packet_count": None,
        "capture_data_size_bytes": None,
        "capture_file_size_bytes": None,
        "capture_encapsulation": None,
    }

    def parse_scaled_number(value: str) -> Optional[int]:
        value = value.strip().replace(",", "")
        match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([kKmMgG]?)$", value)
        if not match:
            return None

        number = float(match.group(1))
        suffix = match.group(2).lower()

        multiplier = 1
        if suffix == "k":
            multiplier = 1_000
        elif suffix == "m":
            multiplier = 1_000_000
        elif suffix == "g":
            multiplier = 1_000_000_000

        return int(number * multiplier)

    def parse_size_to_bytes(value: str) -> Optional[int]:
        """
        Examples:
        '72 MB' -> 72000000
        '71 MB' -> 71000000
        '879 bytes' -> 879
        """
        value = value.strip().replace(",", "")
        match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([KMG]?B|bytes?)$", value, re.IGNORECASE)
        if not match:
            # fallback for plain integer
            m = re.search(r"([0-9]+)", value)
            return int(m.group(1)) if m else None

        number = float(match.group(1))
        unit = match.group(2).lower()

        multiplier = 1
        if unit == "kb":
            multiplier = 1_000
        elif unit == "mb":
            multiplier = 1_000_000
        elif unit == "gb":
            multiplier = 1_000_000_000
        elif unit in ("byte", "bytes", "b"):
            multiplier = 1

        return int(number * multiplier)

    exact_interface_packet_count = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        normalized = re.sub(r"\s*=\s*", ": ", line)

        if normalized.startswith("First packet time:"):
            metadata["capture_first_packet_time"] = normalized.split(":", 1)[1].strip()

        elif normalized.startswith("Last packet time:"):
            metadata["capture_last_packet_time"] = normalized.split(":", 1)[1].strip()

        elif normalized.startswith("Capture duration:"):
            value = normalized.split(":", 1)[1].strip()
            match = re.search(r"([0-9]+(?:\.[0-9]+)?)", value)
            if match:
                metadata["capture_duration_seconds"] = float(match.group(1))

        elif normalized.startswith("File encapsulation:"):
            metadata["capture_encapsulation"] = normalized.split(":", 1)[1].strip()

        elif normalized.startswith("File size:"):
            value = normalized.split(":", 1)[1].strip()
            metadata["capture_file_size_bytes"] = parse_size_to_bytes(value)

        elif normalized.startswith("Data size:"):
            value = normalized.split(":", 1)[1].strip()
            metadata["capture_data_size_bytes"] = parse_size_to_bytes(value)

        elif normalized.startswith("Number of packets:"):
            value = normalized.split(":", 1)[1].strip()
            parsed = parse_scaled_number(value)
            if parsed is not None:
                metadata["capture_packet_count"] = parsed

        elif line.startswith("Number of packets ="):
            value = line.split("=", 1)[1].strip()
            parsed = parse_scaled_number(value)
            if parsed is not None:
                exact_interface_packet_count = parsed

    if exact_interface_packet_count is not None:
        metadata["capture_packet_count"] = exact_interface_packet_count

    return metadata


def run_capinfos(pcap_path: str) -> Dict[str, Optional[object]]:
    cmd = ["capinfos", "-M", "-c", "-a", "-e", pcap_path]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"capinfos failed: {stderr}")

    return parse_capinfos_output(result.stdout)


def extract_and_store_metadata(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)

    try:
        rows = registry.fetch_for_metadata_extraction()
        if not rows:
            print("[INFO] No PCAPs pending metadata extraction.")
            return

        for row in rows:
            pcap_id = row["pcap_id"]
            full_path = row["full_path"]

            print(f"[INFO] Extracting metadata for {pcap_id} | {full_path}")

            try:
                if not Path(full_path).exists():
                    registry.update_metadata(pcap_id, {
                        "metadata_extracted_at": utc_now_iso(),
                        "metadata_tool": "capinfos",
                        "metadata_status": "FAILED",
                        "ingest_status": "METADATA_FAILED",
                        "notes": "File no longer exists at registered path."
                    })
                    print(f"[FAIL] Missing file: {full_path}")
                    continue

                extracted = run_capinfos(full_path)
                extracted.update({
                    "metadata_extracted_at": utc_now_iso(),
                    "metadata_tool": "capinfos",
                    "metadata_status": "SUCCESS",
                    "ingest_status": "METADATA_EXTRACTED",
                    "notes": ""
                })

                registry.update_metadata(pcap_id, extracted)

                print(
                    f"[OK] {pcap_id} | "
                    f"packets={extracted.get('capture_packet_count')} | "
                    f"start={extracted.get('capture_first_packet_time')} | "
                    f"end={extracted.get('capture_last_packet_time')}"
                )

            except Exception as e:
                registry.update_metadata(pcap_id, {
                    "metadata_extracted_at": utc_now_iso(),
                    "metadata_tool": "capinfos",
                    "metadata_status": "FAILED",
                    "ingest_status": "METADATA_FAILED",
                    "notes": str(e)
                })
                print(f"[FAIL] {pcap_id} | {e}")

    finally:
        registry.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract time-bound metadata from registered PCAPs using capinfos."
    )
    parser.add_argument(
        "--db-path",
        default="evidence_registry.db",
        help="Path to SQLite registry database."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    extract_and_store_metadata(db_path=args.db_path)