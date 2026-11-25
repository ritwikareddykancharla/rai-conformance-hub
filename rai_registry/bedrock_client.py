"""Amazon Bedrock Converse client wrapper (`us.amazon.nova-lite-v1:0`) and SQLite WAL hash-chain ledger."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_BEDROCK_MODEL = os.environ.get("RAI_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0")
DEFAULT_AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"
GENESIS_HASH = "GENESIS_RAI_REGISTRY_SQLITE_0000"


def extract_json_object(raw_text: str) -> Optional[Dict[str, Any]]:
    """Extract the first valid JSON object from model prose or fenced markdown."""
    if not raw_text:
        return None
    cleaned = raw_text.strip()
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL)
    if fence_match:
        try:
            obj = json.loads(fence_match.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = cleaned[start : end + 1]
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    return None


def invoke_bedrock_json(
    system_prompt: str,
    user_prompt: str,
    fallback_payload: Dict[str, Any],
    use_bedrock: bool = True,
    max_tokens: int = 650,
    temperature: float = 0.1,
) -> Dict[str, Any]:
    """Call Amazon Bedrock (`us.amazon.nova-lite-v1:0`) via Converse API and parse structured JSON."""
    if not use_bedrock:
        return {
            "parsed": fallback_payload,
            "raw_text": json.dumps(fallback_payload),
            "engine": "deterministic-local-policy",
            "model_id": DEFAULT_BEDROCK_MODEL,
            "latency_ms": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "live_bedrock": False,
        }

    t0 = time.perf_counter()
    aws_err = ""

    # Path 1: boto3 Converse API (AWS Lambda IAM role or exported session credentials)
    try:
        import subprocess
        import shutil
        import boto3  # type: ignore
        from botocore.config import Config  # type: ignore

        cfg = Config(connect_timeout=6, read_timeout=22, retries={"max_attempts": 2})
        try:
            client = boto3.client("bedrock-runtime", region_name=DEFAULT_AWS_REGION, config=cfg)
            resp = client.converse(
                modelId=DEFAULT_BEDROCK_MODEL,
                system=[{"text": system_prompt}],
                messages=[{"role": "user", "content": [{"text": user_prompt}]}],
                inferenceConfig={"maxTokens": max_tokens, "temperature": temperature, "topP": 0.9},
            )
        except Exception as inner_exc:
            # Resolve AWS CLI v2 login/SSO session credentials into boto3 when botocore[crt] is absent locally
            aws_bin = shutil.which("aws")
            if not aws_bin:
                raise inner_exc
            env = dict(os.environ)
            env.pop("AWS_ACCESS_KEY_ID", None)
            env.pop("AWS_SECRET_ACCESS_KEY", None)
            env.pop("AWS_SESSION_TOKEN", None)
            env["AWS_PROFILE"] = os.environ.get("AWS_PROFILE", "portfolio")
            cred_proc = subprocess.run(
                [aws_bin, "configure", "export-credentials", "--profile", env["AWS_PROFILE"], "--format", "process"],
                env=env,
                capture_output=True,
                text=True,
                timeout=6.0,
            )
            if cred_proc.returncode != 0:
                raise inner_exc
            creds = json.loads(cred_proc.stdout)
            t0 = time.perf_counter()
            client = boto3.client(
                "bedrock-runtime",
                region_name=DEFAULT_AWS_REGION,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds.get("SessionToken"),
                config=cfg,
            )
            resp = client.converse(
                modelId=DEFAULT_BEDROCK_MODEL,
                system=[{"text": system_prompt}],
                messages=[{"role": "user", "content": [{"text": user_prompt}]}],
                inferenceConfig={"maxTokens": max_tokens, "temperature": temperature, "topP": 0.9},
            )

        round_trip_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        server_ms = float((resp.get("metrics") or {}).get("latencyMs") or round_trip_ms)
        blocks = ((resp.get("output") or {}).get("message") or {}).get("content") or []
        raw_text = "\n".join(b.get("text", "") for b in blocks if "text" in b).strip()
        usage = resp.get("usage") or {}
        in_tok = int(usage.get("inputTokens") or 0)
        out_tok = int(usage.get("outputTokens") or 0)
        tot_tok = int(usage.get("totalTokens") or (in_tok + out_tok))
        parsed = extract_json_object(raw_text) or fallback_payload
        return {
            "parsed": parsed,
            "raw_text": raw_text,
            "engine": f"bedrock:{DEFAULT_BEDROCK_MODEL}",
            "model_id": DEFAULT_BEDROCK_MODEL,
            "latency_ms": round(server_ms, 2),
            "round_trip_ms": round_trip_ms,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "total_tokens": tot_tok,
            "live_bedrock": True,
        }
    except Exception as exc:
        aws_err = str(exc)

    # Path 2: Direct AWS CLI `bedrock-runtime converse` fallback
    try:
        import shutil
        import subprocess

        aws_bin = shutil.which("aws")
        if aws_bin:
            env = dict(os.environ)
            env.pop("AWS_ACCESS_KEY_ID", None)
            env.pop("AWS_SECRET_ACCESS_KEY", None)
            env.pop("AWS_SESSION_TOKEN", None)
            env["AWS_PROFILE"] = os.environ.get("AWS_PROFILE", "portfolio")
            env["AWS_DEFAULT_REGION"] = DEFAULT_AWS_REGION
            t_cli = time.perf_counter()
            proc = subprocess.run(
                [
                    aws_bin,
                    "bedrock-runtime",
                    "converse",
                    "--region",
                    DEFAULT_AWS_REGION,
                    "--model-id",
                    DEFAULT_BEDROCK_MODEL,
                    "--system",
                    json.dumps([{"text": system_prompt}]),
                    "--messages",
                    json.dumps([{"role": "user", "content": [{"text": user_prompt}]}]),
                    "--inference-config",
                    json.dumps({"maxTokens": max_tokens, "temperature": temperature}),
                    "--output",
                    "json",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=22.0,
            )
            rt_ms = round((time.perf_counter() - t_cli) * 1000.0, 2)
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                srv_ms = float((data.get("metrics") or {}).get("latencyMs") or rt_ms)
                blocks = ((data.get("output") or {}).get("message") or {}).get("content") or []
                raw_text = "\n".join(b.get("text", "") for b in blocks if "text" in b).strip()
                usage = data.get("usage") or {}
                in_tok = int(usage.get("inputTokens") or 0)
                out_tok = int(usage.get("outputTokens") or 0)
                tot_tok = int(usage.get("totalTokens") or (in_tok + out_tok))
                parsed = extract_json_object(raw_text) or fallback_payload
                return {
                    "parsed": parsed,
                    "raw_text": raw_text,
                    "engine": f"bedrock:{DEFAULT_BEDROCK_MODEL}",
                    "model_id": DEFAULT_BEDROCK_MODEL,
                    "latency_ms": round(srv_ms, 2),
                    "round_trip_ms": rt_ms,
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "total_tokens": tot_tok,
                    "live_bedrock": True,
                }
    except Exception as cli_exc:
        aws_err = f"{aws_err}; cli={cli_exc}"

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "parsed": fallback_payload,
        "raw_text": json.dumps(fallback_payload),
        "engine": "deterministic-fallback",
        "error": aws_err,
        "model_id": DEFAULT_BEDROCK_MODEL,
        "latency_ms": elapsed_ms,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "live_bedrock": False,
    }


class GovernanceAuditLedger:
    """Append-only SQLite WAL hash-chained conformance ledger shared across all RAI gates."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        base_dir = Path(os.environ.get("RAI_RUNTIME_DIR", "/tmp/rai-conformance-runtime"))
        base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else (base_dir / "rai_conformance.db")
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS conformance_events (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        recorded_utc TEXT NOT NULL,
                        gate_module TEXT NOT NULL,
                        subject_id TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        duration_ms REAL NOT NULL,
                        summary_json TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        sha256_hash TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    @staticmethod
    def _compute_digest(
        event_id: str,
        recorded_utc: str,
        gate_module: str,
        subject_id: str,
        verdict: str,
        summary_json: str,
        prev_hash: str,
    ) -> str:
        canonical = json.dumps(
            {
                "event_id": event_id,
                "recorded_utc": recorded_utc,
                "gate_module": gate_module,
                "subject_id": subject_id,
                "verdict": verdict,
                "summary_json": summary_json,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append_event(
        self,
        gate_module: str,
        subject_id: str,
        verdict: str,
        duration_ms: float,
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        with self._lock:
            conn = self._connect()
            try:
                last_row = conn.execute(
                    "SELECT seq, sha256_hash FROM conformance_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                next_seq = (int(last_row["seq"]) + 1) if last_row else 1
                prev_hash = str(last_row["sha256_hash"]) if last_row else GENESIS_HASH
                event_id = f"RAI-AUD-{next_seq:05d}"
                recorded_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                summary_json = json.dumps(summary, sort_keys=True, separators=(",", ":"), default=str)
                digest = self._compute_digest(
                    event_id=event_id,
                    recorded_utc=recorded_utc,
                    gate_module=gate_module,
                    subject_id=subject_id,
                    verdict=verdict,
                    summary_json=summary_json,
                    prev_hash=prev_hash,
                )
                conn.execute(
                    """
                    INSERT INTO conformance_events
                    (event_id, recorded_utc, gate_module, subject_id, verdict, duration_ms, summary_json, prev_hash, sha256_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        recorded_utc,
                        gate_module,
                        subject_id,
                        verdict,
                        round(float(duration_ms), 3),
                        summary_json,
                        prev_hash,
                        digest,
                    ),
                )
                conn.commit()
                return {
                    "event_id": event_id,
                    "recorded_utc": recorded_utc,
                    "gate_module": gate_module,
                    "subject_id": subject_id,
                    "verdict": verdict,
                    "duration_ms": round(float(duration_ms), 3),
                    "prev_hash": prev_hash,
                    "sha256_hash": digest,
                }
            finally:
                conn.close()

    def verify_chain(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM conformance_events ORDER BY seq ASC").fetchall()
            finally:
                conn.close()

        expected_prev = GENESIS_HASH
        broken_at: Optional[str] = None
        for r in rows:
            if r["prev_hash"] != expected_prev:
                broken_at = str(r["event_id"])
                break
            recomputed = self._compute_digest(
                event_id=str(r["event_id"]),
                recorded_utc=str(r["recorded_utc"]),
                gate_module=str(r["gate_module"]),
                subject_id=str(r["subject_id"]),
                verdict=str(r["verdict"]),
                summary_json=str(r["summary_json"]),
                prev_hash=str(r["prev_hash"]),
            )
            if recomputed != str(r["sha256_hash"]):
                broken_at = str(r["event_id"])
                break
            expected_prev = str(r["sha256_hash"])

        verify_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return {
            "valid": broken_at is None,
            "checked_rows": len(rows),
            "broken_at_event_id": broken_at,
            "genesis_hash": GENESIS_HASH,
            "head_hash": expected_prev,
            "verify_ms": verify_ms,
        }

    def recent_events(self, limit: int = 16) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM conformance_events ORDER BY seq DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
            finally:
                conn.close()
        return [
            {
                "event_id": r["event_id"],
                "recorded_utc": r["recorded_utc"],
                "gate_module": r["gate_module"],
                "subject_id": r["subject_id"],
                "verdict": r["verdict"],
                "duration_ms": r["duration_ms"],
                "prev_hash": r["prev_hash"],
                "sha256_hash": r["sha256_hash"],
            }
            for r in rows
        ]

    def reset(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM conformance_events;")
                conn.execute("DELETE FROM sqlite_sequence WHERE name='conformance_events';")
                conn.commit()
            finally:
                conn.close()
