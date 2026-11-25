"""HTTP Server & AWS CloudFront `/api/*` Lambda Origin Handler for ResponsibleAIRegistry."""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .bedrock_client import DEFAULT_AWS_REGION, DEFAULT_BEDROCK_MODEL, GovernanceAuditLedger
from .fairness_metrics import FAIRNESS_SCENARIO_SPECS, run_fairness_audit
from .risk_conformance import GOLDEN_RISK_SYSTEMS, classify_ai_system_risk
from .shadow_ai_bom import SYNTHETIC_FLEET_REPOS, AIBomRegistry
from .sop_artifact_distiller import CS_POLICY_BUNDLES, distill_policy_bundle

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"
BENCH_FILE = ROOT_DIR / "benchmarks" / "latest_results.json"

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


class RAIConformanceHubService:
    """Stateful control plane coordinating AI-BOM discovery, Risk Gate, Fairness Engine, SOP Distiller, and SQLite WAL Ledger."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.ledger = GovernanceAuditLedger(db_path=db_path)
        self.bom_registry = AIBomRegistry(db_path=self.ledger.db_path)
        self._seed_initial_ledger_if_empty()

    def _seed_initial_ledger_if_empty(self) -> None:
        if self.ledger.recent_events(limit=1):
            return
        r1 = self.bom_registry.scan_workload(
            service_id=SYNTHETIC_FLEET_REPOS[1]["service_id"],
            python_code=SYNTHETIC_FLEET_REPOS[1]["python_code"],
            iac_template=SYNTHETIC_FLEET_REPOS[1]["iac_template"],
            deploy_region=SYNTHETIC_FLEET_REPOS[1]["deploy_region"],
            repo_id=SYNTHETIC_FLEET_REPOS[1]["repo_id"],
            use_bedrock=False,
        )
        self.ledger.append_event(
            gate_module="shadow_ai_bom",
            subject_id=r1["service_id"],
            verdict=r1["conformance_status"],
            duration_ms=r1["scan_ms"],
            summary={"findings": len(r1["findings"])},
        )
        r2 = classify_ai_system_risk(GOLDEN_RISK_SYSTEMS[3], use_bedrock=False)
        self.ledger.append_event(
            gate_module="risk_conformance",
            subject_id=r2["system_id"],
            verdict=f"{r2['risk_tier']}:{r2['release_verdict']}",
            duration_ms=r2["policy_eval_ms"],
            summary={"missing_controls": r2["missing_controls"]},
        )
        r3 = run_fairness_audit("resume_screening_v2", base_threshold=0.50, mitigate=True)
        self.ledger.append_event(
            gate_module="fairness_metrics",
            subject_id="resume_screening_v2",
            verdict=r3["final_verdict"],
            duration_ms=r3["audit_ms"],
            summary={
                "di_before": r3["baseline_metrics"]["disparate_impact_ratio"],
                "di_after": r3["mitigated_metrics"]["disparate_impact_ratio"],
            },
        )

    def load_benchmarks(self) -> Dict[str, Any]:
        if BENCH_FILE.is_file():
            try:
                return json.loads(BENCH_FILE.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return {"service": "rai-conformance-hub", "status": "benchmarks_not_generated_yet"}

    def get_state_snapshot(self) -> Dict[str, Any]:
        chain = self.ledger.verify_chain()
        return {
            "service": "rai-conformance-hub",
            "approved_ai_bom": self.bom_registry.list_approved_systems(),
            "fleet_repos": [
                {
                    "repo_id": r["repo_id"],
                    "service_id": r["service_id"],
                    "title": r["title"],
                    "deploy_region": r["deploy_region"],
                    "expected_status": r["expected_status"],
                    "python_code": r["python_code"],
                    "iac_template": r["iac_template"],
                }
                for r in SYNTHETIC_FLEET_REPOS
            ],
            "risk_presets": GOLDEN_RISK_SYSTEMS[:8],
            "fairness_scenarios": [
                {"scenario_id": k, "title": v["title"], "eu_annex": v["eu_annex"]}
                for k, v in FAIRNESS_SCENARIO_SPECS.items()
            ],
            "sop_bundles": [
                {
                    "policy_family": k,
                    "title": v["title"],
                    "locales": {loc: spec["sop_prose"] for loc, spec in v["locales"].items()},
                }
                for k, v in CS_POLICY_BUNDLES.items()
            ],
            "audit_chain": chain,
            "audit_events": self.ledger.recent_events(limit=18),
            "benchmarks": self.load_benchmarks(),
        }

    def reset(self) -> None:
        self.ledger.reset()
        self.bom_registry._init_and_seed()
        self._seed_initial_ledger_if_empty()


HUB = RAIConformanceHubService()


def route_api_request(
    method: str,
    path: str,
    query: Dict[str, str],
    body: Dict[str, Any],
    request_id: str = "local",
    hub: Optional[RAIConformanceHubService] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Pure HTTP/Lambda API router serving all ResponsibleAIRegistry endpoints."""
    svc = hub or HUB
    try:
        if method == "GET" and path == "/api/health":
            chain = svc.ledger.verify_chain()
            approved = svc.bom_registry.list_approved_systems()
            return 200, {
                "status": "ok",
                "service": "rai-conformance-hub",
                "delivery": os.environ.get("RAI_DELIVERY", "cloudfront-s3-oac + lambda-api-origin"),
                "aws_region": DEFAULT_AWS_REGION,
                "bedrock_model": DEFAULT_BEDROCK_MODEL,
                "python_version": platform.python_version(),
                "registered_ai_systems": len(approved),
                "sqlite_ledger_valid": chain["valid"],
                "sqlite_ledger_rows": chain["checked_rows"],
                "request_id": request_id,
            }

        if method == "GET" and path == "/api/state":
            snap = svc.get_state_snapshot()
            snap["request_id"] = request_id
            return 200, snap

        if method == "GET" and path == "/api/benchmarks":
            bench = svc.load_benchmarks()
            bench["audit_chain"] = svc.ledger.verify_chain()
            bench["request_id"] = request_id
            return 200, bench

        if method == "POST" and path == "/api/bom/discover":
            if bool(body.get("scan_all", False)):
                out = svc.bom_registry.scan_synthetic_fleet(
                    use_bedrock_on_flagged=bool(body.get("use_bedrock", False))
                )
                receipt = svc.ledger.append_event(
                    gate_module="shadow_ai_bom",
                    subject_id="fleet-12-repos",
                    verdict=f"SHADOW:{out['shadow_unregistered']}|DRIFT:{out['drift_violations']}",
                    duration_ms=out["total_scan_ms"],
                    summary={
                        "repos_scanned": out["repos_scanned"],
                        "accuracy_pct": out["discovery_accuracy_pct"],
                    },
                )
                out["audit_receipt"] = receipt
                out["request_id"] = request_id
                return 200, out

            repo_id = str(body.get("repo_id") or "").strip()
            preset = next((r for r in SYNTHETIC_FLEET_REPOS if r["repo_id"] == repo_id), None)

            python_code = str(body.get("python_code") if "python_code" in body else (preset["python_code"] if preset else "")).strip()
            if not python_code:
                return 400, {"error": "Provide repo_id, scan_all=true, or python_code to scan"}

            raw_iac = body.get("iac_template", preset["iac_template"] if preset else {})
            if isinstance(raw_iac, str):
                iac_template = json.loads(raw_iac) if raw_iac.strip() else {}
            elif isinstance(raw_iac, dict):
                iac_template = raw_iac
            else:
                iac_template = {}

            service_id = str(body.get("service_id") or (preset["service_id"] if preset else "custom-service")).strip()
            deploy_region = str(body.get("deploy_region") or (preset["deploy_region"] if preset else "us-west-2")).strip()
            use_bedrock = bool(body.get("use_bedrock", True))

            out = svc.bom_registry.scan_workload(
                service_id=service_id,
                python_code=python_code,
                iac_template=iac_template,
                deploy_region=deploy_region,
                repo_id=repo_id or "custom-repo",
                use_bedrock=use_bedrock,
            )
            receipt = svc.ledger.append_event(
                gate_module="shadow_ai_bom",
                subject_id=service_id,
                verdict=out["conformance_status"],
                duration_ms=out["scan_ms"],
                summary={"findings_count": len(out["findings"]), "region": deploy_region},
            )
            out["audit_receipt"] = receipt
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/risk/classify":
            preset_id = str(body.get("system_id") or "").strip()
            preset_sys = next((s for s in GOLDEN_RISK_SYSTEMS if s["system_id"] == preset_id), None)
            manifest = dict(preset_sys) if (preset_sys and "description" not in body) else dict(body)
            if not manifest.get("description") and not manifest.get("domain"):
                return 400, {"error": "Provide system_id or manifest with domain and description"}

            use_bedrock = bool(body.get("use_bedrock", True))
            out = classify_ai_system_risk(manifest, use_bedrock=use_bedrock)
            receipt = svc.ledger.append_event(
                gate_module="risk_conformance",
                subject_id=out["system_id"],
                verdict=f"{out['risk_tier']}:{out['release_verdict']}",
                duration_ms=out["policy_eval_ms"] + out["bedrock_latency_ms"],
                summary={"missing_controls": out["missing_controls"]},
            )
            out["audit_receipt"] = receipt
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/fairness/audit":
            scenario_id = str(body.get("scenario_id") or "resume_screening_v2").strip()
            base_threshold = float(body.get("base_threshold", 0.50))
            mitigate = bool(body.get("mitigate", True))
            custom_records = body.get("records") if isinstance(body.get("records"), list) else None

            out = run_fairness_audit(
                scenario_id=scenario_id,
                base_threshold=base_threshold,
                mitigate=mitigate,
                custom_records=custom_records,
            )
            receipt = svc.ledger.append_event(
                gate_module="fairness_metrics",
                subject_id=scenario_id,
                verdict=out["final_verdict"],
                duration_ms=out["audit_ms"],
                summary={
                    "di_baseline": out["baseline_metrics"]["disparate_impact_ratio"],
                    "di_mitigated": out["mitigated_metrics"]["disparate_impact_ratio"] if out["mitigated_metrics"] else None,
                    "f1_delta": out["f1_tradeoff_delta"],
                },
            )
            out["audit_receipt"] = receipt
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/artifacts/distill":
            policy_family = str(body.get("policy_family") or "electronics_returns").strip()
            custom_sop = str(body.get("sop_text") or "").strip() or None
            custom_locale = str(body.get("locale") or "en-US").strip()
            use_bedrock = bool(body.get("use_bedrock", True))

            out = distill_policy_bundle(
                policy_family=policy_family,
                custom_sop_text=custom_sop,
                custom_locale=custom_locale,
                use_bedrock=use_bedrock,
            )
            receipt = svc.ledger.append_event(
                gate_module="sop_artifact_distiller",
                subject_id=f"{policy_family}:{custom_locale}",
                verdict=out["publish_verdict"],
                duration_ms=out["total_distill_ms"],
                summary=out["metrics"],
            )
            out["audit_receipt"] = receipt
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/reset":
            svc.reset()
            return 200, {
                "status": "reset_complete",
                "service": "rai-conformance-hub",
                "request_id": request_id,
            }

        return 404, {"error": f"Unknown API route: {method} {path}"}
    except SyntaxError as exc:
        return 400, {"error": f"Python AST parse error at line {exc.lineno}: {exc.msg}"}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except Exception as exc:
        return 500, {"error": str(exc)}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL handler mounted behind Amazon CloudFront `/api/*` origin."""
    req_ctx = event.get("requestContext") or {}
    method = ((req_ctx.get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = {k: str(v) for k, v in (event.get("queryStringParameters") or {}).items() if v is not None}
    req_id = getattr(context, "aws_request_id", "cloudfront-api")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if raw_path.startswith("/api/"):
        body: Dict[str, Any] = {}
        raw_body = event.get("body")
        if raw_body:
            if event.get("isBase64Encoded") and isinstance(raw_body, str):
                raw_body = base64.b64decode(raw_body).decode("utf-8")
            body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        status, payload = route_api_request(method, raw_path, query_params, body, request_id=req_id)
        return {
            "statusCode": status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
            "body": json.dumps(payload, default=str),
        }

    target = WEB_DIR / ("index.html" if raw_path in ("/", "") else raw_path.lstrip("/"))
    if not target.is_file() and raw_path.endswith(".svg"):
        target = DOCS_DIR / Path(raw_path).name
    if target.is_file():
        ctype = mimetypes.guess_type(str(target))[0] or "text/html; charset=utf-8"
        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": ctype},
            "body": target.read_text(encoding="utf-8"),
        }
    return {
        "statusCode": 404,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps({"error": "Not found", "path": raw_path}),
    }


class LocalRAIHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path.startswith("/api/"):
            status, payload = route_api_request("GET", path, query, {}, request_id="local-dev")
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        candidate = (WEB_DIR / rel).resolve()
        if not candidate.is_file() and path.endswith(".svg"):
            candidate = (DOCS_DIR / Path(path).name).resolve()
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"

        data = candidate.read_bytes()
        ctype = mimetypes.guess_type(str(candidate))[0] or "text/html"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw_body) if raw_body.strip() else {}
        status, payload = route_api_request("POST", parsed.path, {}, body, request_id="local-dev")
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_local_server(port: int = 3099) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), LocalRAIHandler)
    print(f"ResponsibleAIRegistry running at http://localhost:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    port_num = int(os.environ.get("PORT", "3099"))
    run_local_server(port=port_num)
