"""Comprehensive unit test suite (12 tests) for ResponsibleAIRegistry (`rai_registry`)."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rai_registry.bedrock_client import GovernanceAuditLedger
from rai_registry.fairness_metrics import run_fairness_audit
from rai_registry.risk_conformance import (
    GOLDEN_RISK_SYSTEMS,
    classify_ai_system_risk,
    evaluate_golden_risk_suite,
)
from rai_registry.server import RAIConformanceHubService, lambda_handler, route_api_request
from rai_registry.shadow_ai_bom import SYNTHETIC_FLEET_REPOS, AIBomRegistry
from rai_registry.sop_artifact_distiller import (
    detect_cross_locale_conflicts,
    distill_policy_bundle,
    verify_artifact_entailment,
)


class TestResponsibleAIRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_rai.db"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_01_ast_shadow_ai_detects_unregistered_external_sdk_and_sinks(self) -> None:
        reg = AIBomRegistry(db_path=self.db_path)
        shadow_repo = SYNTHETIC_FLEET_REPOS[1]  # repo-02-shadow-hr-screener
        res = reg.scan_workload(
            service_id=shadow_repo["service_id"],
            python_code=shadow_repo["python_code"],
            iac_template=shadow_repo["iac_template"],
            deploy_region=shadow_repo["deploy_region"],
            repo_id=shadow_repo["repo_id"],
            use_bedrock=False,
        )
        self.assertEqual(res["conformance_status"], "SHADOW_UNREGISTERED")
        self.assertFalse(res["registered_in_bom"])
        codes = {f["code"] for f in res["findings"]}
        self.assertIn("BOM-SHADOW-001", codes)
        self.assertIn("BOM-EXT-API-002", codes)
        self.assertIn("BOM-RETENTION-007", codes)
        self.assertIn("openai-python-sdk", res["ai_bom_entry"]["external_sdks"])
        self.assertIn("auto_reject_applicant_ats", res["ai_bom_entry"]["agent_tools"])

    def test_02_ast_and_iac_drift_detection_on_registered_workload(self) -> None:
        reg = AIBomRegistry(db_path=self.db_path)
        drifted_repo = SYNTHETIC_FLEET_REPOS[4]  # prime-support-summarizer deployed to eu-central-1 without guardrail
        res = reg.scan_workload(
            service_id=drifted_repo["service_id"],
            python_code=drifted_repo["python_code"],
            iac_template=drifted_repo["iac_template"],
            deploy_region=drifted_repo["deploy_region"],
            repo_id=drifted_repo["repo_id"],
            use_bedrock=False,
        )
        self.assertTrue(res["registered_in_bom"])
        self.assertEqual(res["conformance_status"], "DRIFT_VIOLATION")
        codes = {f["code"] for f in res["findings"]}
        self.assertIn("BOM-REGION-DRIFT-003", codes)
        self.assertIn("BOM-GUARDRAIL-005", codes)
        self.assertIn("BOM-RETENTION-007", codes)

    def test_03_synthetic_12_repo_fleet_scan_matches_ground_truth(self) -> None:
        reg = AIBomRegistry(db_path=self.db_path)
        summary = reg.scan_synthetic_fleet(use_bedrock_on_flagged=False)
        self.assertEqual(summary["repos_scanned"], 12)
        self.assertEqual(summary["classification_matches"], 12)
        self.assertEqual(summary["discovery_accuracy_pct"], 100.0)
        self.assertEqual(summary["shadow_unregistered"], 5)
        self.assertEqual(summary["drift_violations"], 3)
        self.assertEqual(summary["compliant_registered"], 4)

    def test_04_eu_ai_act_prohibited_and_high_risk_release_blocking(self) -> None:
        prohibited = classify_ai_system_risk(GOLDEN_RISK_SYSTEMS[0], use_bedrock=False)
        self.assertEqual(prohibited["risk_tier"], "PROHIBITED")
        self.assertEqual(prohibited["release_verdict"], "BLOCK_PROHIBITED_USE")

        uncontrolled_hr = classify_ai_system_risk(GOLDEN_RISK_SYSTEMS[4], use_bedrock=False)
        self.assertEqual(uncontrolled_hr["risk_tier"], "HIGH_RISK")
        self.assertEqual(uncontrolled_hr["release_verdict"], "BLOCK_MISSING_CONTROLS")
        self.assertIn("human_in_the_loop_override", uncontrolled_hr["missing_controls"])
        self.assertIn("subgroup_fairness_audit", uncontrolled_hr["missing_controls"])

    def test_05_golden_16_system_risk_conformance_suite_accuracy(self) -> None:
        suite = evaluate_golden_risk_suite(use_bedrock_sample=False)
        self.assertEqual(suite["systems_evaluated"], 16)
        self.assertEqual(suite["tier_accuracy_pct"], 100.0)
        self.assertEqual(suite["verdict_accuracy_pct"], 100.0)
        self.assertEqual(suite["high_risk_and_prohibited_recall_pct"], 100.0)

    def test_06_subgroup_fairness_4000_row_audit_and_threshold_mitigation(self) -> None:
        audit = run_fairness_audit("resume_screening_v2", base_threshold=0.50, mitigate=True)
        self.assertEqual(audit["rows_evaluated"], 4000)
        base = audit["baseline_metrics"]
        mit = audit["mitigated_metrics"]
        self.assertIsNotNone(mit)

        # Unmitigated uniform 0.50 threshold violates EEOC 4/5ths (0.80) rule
        self.assertLess(base["disparate_impact_ratio"], 0.80)
        self.assertEqual(base["fairness_verdict"], "FAIL_FAIRNESS_VIOLATION")

        # Post-processing group thresholds restore >= 0.80 DI and Equalized Odds compliance with minimal F1 delta
        self.assertGreaterEqual(mit["disparate_impact_ratio"], 0.80)
        self.assertLessEqual(mit["equal_opportunity_diff_tpr"], 0.06)
        self.assertEqual(mit["fairness_verdict"], "PASS_FAIRNESS")
        self.assertLess(abs(audit["f1_tradeoff_delta"]), 0.04)

    def test_07_fairness_seller_credit_and_ece_computation(self) -> None:
        audit = run_fairness_audit("seller_credit_underwriting", base_threshold=0.50, mitigate=True)
        self.assertEqual(audit["rows_evaluated"], 4000)
        self.assertGreater(audit["baseline_metrics"]["overall_ece"], 0.0)
        self.assertLess(audit["baseline_metrics"]["overall_ece"], 0.25)
        self.assertEqual(audit["final_verdict"], "PASS_FAIRNESS")

    def test_08_sop_entailment_verifier_rejects_hallucinated_numbers(self) -> None:
        sop_text = (
            "Customers in the US may return unopened electronics within 30 days for a 0% restocking fee. "
            "Opened physical software is non-refundable."
        )
        bad_artifact = {
            "artifact_id": "KA-TEST",
            "refund_window_days": 60,  # Hallucinated 60 not in SOP
            "restocking_fee_pct": 0,
            "exceptions": ["opened_physical_software_non_refundable"],
            "required_disclosures": ["standard_cs_policy_receipt"],
            "source_span": {"start_char": 0, "end_char": 60, "verbatim_quote": "return unopened electronics within 30 days"},
        }
        ver = verify_artifact_entailment(sop_text, bad_artifact)
        self.assertFalse(ver["entailed"])
        self.assertEqual(ver["numeric_precision_pct"], 0.0)
        self.assertIn("refund_window_days=60", ver["ungrounded_numbers"])

    def test_09_multi_locale_conflict_detector_flags_us_drift_and_eu_14d_breach(self) -> None:
        ret_bundle = distill_policy_bundle("electronics_returns", use_bedrock=False)
        self.assertEqual(ret_bundle["publish_verdict"], "BLOCK_LOCALE_CONFLICT")
        conflict_ids = {c["conflict_id"] for c in ret_bundle["cross_locale_conflicts"]}
        self.assertIn("LOCALE-DRIFT-US-WINDOW", conflict_ids)
        self.assertIn("LOCALE-DRIFT-US-EXCEPTIONS", conflict_ids)
        self.assertEqual(ret_bundle["metrics"]["numeric_entailment_precision_pct"], 100.0)
        self.assertEqual(ret_bundle["metrics"]["exception_clause_recall_pct"], 100.0)

        sub_bundle = distill_policy_bundle("digital_subscriptions_refund", use_bedrock=False)
        sub_conflict_ids = {c["conflict_id"] for c in sub_bundle["cross_locale_conflicts"]}
        self.assertIn("STATUTORY-EU-14D-BREACH", sub_conflict_ids)

    def test_10_sqlite_wal_hash_chain_detects_single_row_tampering(self) -> None:
        ledger = GovernanceAuditLedger(db_path=self.db_path)
        e1 = ledger.append_event("shadow_ai_bom", "svc-a", "COMPLIANT_REGISTERED", 1.2, {"ok": True})
        ledger.append_event("risk_conformance", "svc-b", "HIGH_RISK:PASS_RELEASE", 0.8, {"controls": 6})
        self.assertTrue(ledger.verify_chain()["valid"])

        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                "UPDATE conformance_events SET verdict = 'TAMPERED_PASS' WHERE event_id = ?",
                (e1["event_id"],),
            )
            conn.commit()
        finally:
            conn.close()

        tampered_check = ledger.verify_chain()
        self.assertFalse(tampered_check["valid"])
        self.assertEqual(tampered_check["broken_at_event_id"], e1["event_id"])

    def test_11_api_router_endpoints_and_reset(self) -> None:
        hub = RAIConformanceHubService(db_path=self.db_path)
        st, health = route_api_request("GET", "/api/health", {}, {}, hub=hub)
        self.assertEqual(st, 200)
        self.assertEqual(health["status"], "ok")
        self.assertTrue(health["sqlite_ledger_valid"])

        st, bom_res = route_api_request(
            "POST",
            "/api/bom/discover",
            {},
            {"repo_id": "repo-02-shadow-hr-screener", "use_bedrock": False},
            hub=hub,
        )
        self.assertEqual(st, 200)
        self.assertEqual(bom_res["conformance_status"], "SHADOW_UNREGISTERED")

        st, risk_res = route_api_request(
            "POST",
            "/api/risk/classify",
            {},
            {"system_id": "sys-04-candidate-resume-ranker-compliant", "use_bedrock": False},
            hub=hub,
        )
        self.assertEqual(st, 200)
        self.assertEqual(risk_res["risk_tier"], "HIGH_RISK")
        self.assertEqual(risk_res["release_verdict"], "PASS_RELEASE")

        st, fair_res = route_api_request(
            "POST",
            "/api/fairness/audit",
            {},
            {"scenario_id": "resume_screening_v2", "mitigate": True},
            hub=hub,
        )
        self.assertEqual(st, 200)
        self.assertEqual(fair_res["final_verdict"], "PASS_FAIRNESS")

        st, dist_res = route_api_request(
            "POST",
            "/api/artifacts/distill",
            {},
            {"policy_family": "electronics_returns", "use_bedrock": False},
            hub=hub,
        )
        self.assertEqual(st, 200)
        self.assertEqual(dist_res["publish_verdict"], "BLOCK_LOCALE_CONFLICT")

    def test_12_lambda_handler_cloudfront_proxy_format(self) -> None:
        resp = lambda_handler(
            {
                "rawPath": "/api/health",
                "requestContext": {"http": {"method": "GET"}},
            }
        )
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(resp["body"])
        self.assertEqual(payload["service"], "rai-conformance-hub")


if __name__ == "__main__":
    unittest.main()
