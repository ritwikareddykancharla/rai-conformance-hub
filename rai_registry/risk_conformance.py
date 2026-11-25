"""Policy-as-Code + Calibrated Bedrock EU AI Act & NIST AI RMF Risk Classifier and Release Gate."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from .bedrock_client import invoke_bedrock_json

RISK_SEVERITY_ORDER = {
    "MINIMAL_RISK": 0,
    "TRANSPARENCY_LIMITED": 1,
    "HIGH_RISK": 2,
    "PROHIBITED": 3,
}

PROHIBITED_SIGNALS_MAP = {
    "social_scoring": "EU AI Act Art. 5(1)(c): Social scoring of natural persons",
    "workplace_emotion_recognition": "EU AI Act Art. 5(1)(f): Emotion inference in workplace or education",
    "subliminal_manipulation": "EU AI Act Art. 5(1)(a): Subliminal or deceptive dark-pattern manipulation",
    "untargeted_facial_scraping": "EU AI Act Art. 5(1)(e): Untargeted scraping of facial images for biometric DBs",
}

HIGH_RISK_DOMAINS_MAP = {
    "employment_hiring": {
        "eu_article": "EU AI Act Art. 6(2) & Annex III §4(a): Recruitment, candidate screening, and task allocation",
        "nist_controls": ["GOVERN-1.2", "MAP-1.1", "MEASURE-2.11 (Fairness)", "MANAGE-2.4 (Human Override)"],
        "rai_dimensions": ["Fairness", "Explainability", "Transparency", "Controllability", "Governance", "Privacy"],
    },
    "credit_underwriting": {
        "eu_article": "EU AI Act Art. 6(2) & Annex III §5(b): Creditworthiness and lending risk assessment",
        "nist_controls": ["GOVERN-1.3", "MAP-3.4", "MEASURE-2.6 (Calibration)", "MEASURE-2.11 (Disparate Impact)", "MANAGE-4.1"],
        "rai_dimensions": ["Fairness", "Explainability", "Robustness", "Veracity", "Controllability", "Governance"],
    },
    "medical_triage": {
        "eu_article": "EU AI Act Art. 6(2) & Annex III §5(a): Emergency healthcare patient triage and benefit eligibility",
        "nist_controls": ["GOVERN-1.2", "MAP-2.3", "MEASURE-2.5 (Safety)", "MANAGE-2.4 (Clinician Override)"],
        "rai_dimensions": ["Safety", "Robustness", "Veracity", "Fairness", "Controllability", "Privacy"],
    },
    "critical_infrastructure": {
        "eu_article": "EU AI Act Art. 6(2) & Annex III §2: Safety components in critical power, water, or transport dispatch",
        "nist_controls": ["GOVERN-1.4", "MAP-3.5", "MEASURE-2.7 (Resilience)", "MANAGE-2.4 (Kill-Switch)"],
        "rai_dimensions": ["Safety", "Robustness", "Controllability", "Security", "Governance"],
    },
    "biometric_identification": {
        "eu_article": "EU AI Act Art. 6(2) & Annex III §1: Biometric categorization and identity verification",
        "nist_controls": ["GOVERN-1.2", "MAP-1.5", "MEASURE-2.11 (Subgroup FPR/FNR)", "MANAGE-3.2"],
        "rai_dimensions": ["Fairness", "Privacy", "Security", "Robustness", "Governance"],
    },
}

REQUIRED_CONTROLS_BY_TIER: Dict[str, List[str]] = {
    "PROHIBITED": ["PROHIBITED_UNDER_EU_AI_ACT_ART_5_NO_CONTROLS_PERMIT_LAUNCH"],
    "HIGH_RISK": [
        "human_in_the_loop_override",
        "subgroup_fairness_audit",
        "technical_documentation_annex_iv",
        "immutable_decision_logging",
        "post_market_drift_monitor",
        "bedrock_guardrail_attached",
    ],
    "TRANSPARENCY_LIMITED": [
        "ai_interaction_disclosure_banner",
        "bedrock_guardrail_attached",
        "synthetic_content_provenance_tag",
    ],
    "MINIMAL_RISK": [
        "ai_bom_registration",
    ],
}

HUMAN_OVERSIGHT_BY_TIER: Dict[str, str] = {
    "PROHIBITED": "Deployment banned under EU AI Act Article 5; workload must be decommissioned immediately.",
    "HIGH_RISK": "Mandatory EU AI Act Article 14 human-in-the-loop oversight: trained reviewer can inspect feature attributions, override individual decisions, and trigger an emergency stop.",
    "TRANSPARENCY_LIMITED": "Mandatory EU AI Act Article 50 disclosure: notify users clearly that they are interacting with an AI system and watermark synthetic outputs.",
    "MINIMAL_RISK": "Standard operational ownership and central AI-BOM registration under EU AI Act Article 95 voluntary code of conduct.",
}


# 16 golden regulatory benchmark systems spanning all 4 EU AI Act tiers
GOLDEN_RISK_SYSTEMS: List[Dict[str, Any]] = [
    {
        "system_id": "sys-01-workplace-emotion-cam",
        "title": "Fulfillment Breakroom Webcam Emotion & Fatigue Scorer",
        "domain": "workplace_surveillance",
        "description": "Analyzes employee facial expressions on breakroom cameras to infer emotional sentiment and motivation scores.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": False,
        "autonomous_decision": True,
        "prohibited_signals": ["workplace_emotion_recognition"],
        "controls_present": ["ai_bom_registration"],
        "expected_tier": "PROHIBITED",
        "expected_verdict": "BLOCK_PROHIBITED_USE",
    },
    {
        "system_id": "sys-02-buyer-social-trust-score",
        "title": "Cross-Platform Citizen Social Behavior Trust Ranker",
        "domain": "consumer_scoring",
        "description": "Aggregates unrelated off-platform social behavior to assign natural persons a civic trustworthiness score.",
        "jurisdictions": ["EU"],
        "human_facing_genai": False,
        "autonomous_decision": True,
        "prohibited_signals": ["social_scoring"],
        "controls_present": ["immutable_decision_logging"],
        "expected_tier": "PROHIBITED",
        "expected_verdict": "BLOCK_PROHIBITED_USE",
    },
    {
        "system_id": "sys-03-subliminal-checkout-nudge",
        "title": "Subliminal Audio-Visual Impulse Spend Manipulator",
        "domain": "consumer_ui",
        "description": "Uses subliminal dark-pattern stimuli targeting vulnerable users to induce unintended high-cost purchases.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": True,
        "autonomous_decision": True,
        "prohibited_signals": ["subliminal_manipulation"],
        "controls_present": [],
        "expected_tier": "PROHIBITED",
        "expected_verdict": "BLOCK_PROHIBITED_USE",
    },
    {
        "system_id": "sys-04-candidate-resume-ranker-compliant",
        "title": "Engineering Candidate Resume Screener (Full Annex III Controls)",
        "domain": "employment_hiring",
        "description": "Ranks incoming SDE job applications and highlights skill matches for human technical recruiters.",
        "jurisdictions": ["EU", "US-CO", "US-WA"],
        "human_facing_genai": False,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": [
            "human_in_the_loop_override",
            "subgroup_fairness_audit",
            "technical_documentation_annex_iv",
            "immutable_decision_logging",
            "post_market_drift_monitor",
            "bedrock_guardrail_attached",
        ],
        "expected_tier": "HIGH_RISK",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-05-candidate-resume-ranker-missing-hitl",
        "title": "Automated Warehouse Applicant Auto-Rejector (Missing Fairness & Override)",
        "domain": "employment_hiring",
        "description": "Automatically rejects seasonal warehouse applicants without recruiter review or disparate impact testing.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": False,
        "autonomous_decision": True,
        "prohibited_signals": [],
        "controls_present": ["immutable_decision_logging"],
        "expected_tier": "HIGH_RISK",
        "expected_verdict": "BLOCK_MISSING_CONTROLS",
    },
    {
        "system_id": "sys-06-seller-credit-underwriter-compliant",
        "title": "Marketplace Seller Working-Capital Credit Underwriter (Verified)",
        "domain": "credit_underwriting",
        "description": "Evaluates sole-proprietor seller cashflow for working-capital loans with calibrated fairness thresholds and underwriter override.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": False,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": [
            "human_in_the_loop_override",
            "subgroup_fairness_audit",
            "technical_documentation_annex_iv",
            "immutable_decision_logging",
            "post_market_drift_monitor",
            "bedrock_guardrail_attached",
        ],
        "expected_tier": "HIGH_RISK",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-07-clinic-triage-missing-docs",
        "title": "Telehealth Urgent Symptom Severity Triage Classifier",
        "domain": "medical_triage",
        "description": "Prioritizes urgent telehealth patient intake queues based on reported cardiopulmonary symptoms.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": True,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": ["human_in_the_loop_override", "bedrock_guardrail_attached"],
        "expected_tier": "HIGH_RISK",
        "expected_verdict": "BLOCK_MISSING_CONTROLS",
    },
    {
        "system_id": "sys-08-grid-load-dispatch-compliant",
        "title": "Microgrid Substation Thermal Safety Load Dispatcher",
        "domain": "critical_infrastructure",
        "description": "Controls real-time battery discharge and breaker trip recommendations on regional substation transformers.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": False,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": [
            "human_in_the_loop_override",
            "subgroup_fairness_audit",
            "technical_documentation_annex_iv",
            "immutable_decision_logging",
            "post_market_drift_monitor",
            "bedrock_guardrail_attached",
        ],
        "expected_tier": "HIGH_RISK",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-09-seller-kyc-biometric-unverified",
        "title": "Remote Seller Passport Biometric Liveness Matcher",
        "domain": "biometric_identification",
        "description": "Matches seller selfie video against government ID photos during marketplace onboarding.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": False,
        "autonomous_decision": True,
        "prohibited_signals": [],
        "controls_present": ["immutable_decision_logging", "bedrock_guardrail_attached"],
        "expected_tier": "HIGH_RISK",
        "expected_verdict": "BLOCK_MISSING_CONTROLS",
    },
    {
        "system_id": "sys-10-cs-refund-chatbot-compliant",
        "title": "Customer Service Multi-Locale Return & Refund Assistant",
        "domain": "customer_support_chatbot",
        "description": "Conversational GenAI support bot answering order return questions using verified Knowledge Artifacts.",
        "jurisdictions": ["EU", "US", "JP"],
        "human_facing_genai": True,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": [
            "ai_interaction_disclosure_banner",
            "bedrock_guardrail_attached",
            "synthetic_content_provenance_tag",
        ],
        "expected_tier": "TRANSPARENCY_LIMITED",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-11-cs-voicebot-missing-disclosure",
        "title": "Outbound Delivery Rescheduling Voice Assistant (Undisclosed AI)",
        "domain": "customer_support_chatbot",
        "description": "Synthetic voice assistant calling customers to reschedule missed deliveries without AI disclosure.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": True,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": ["bedrock_guardrail_attached"],
        "expected_tier": "TRANSPARENCY_LIMITED",
        "expected_verdict": "BLOCK_MISSING_CONTROLS",
    },
    {
        "system_id": "sys-12-product-lifestyle-image-gen",
        "title": "Seller Studio Synthetic Product Background Generator",
        "domain": "synthetic_media_generation",
        "description": "Generates synthetic studio backgrounds for merchant product photos with C2PA provenance metadata.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": True,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": [
            "ai_interaction_disclosure_banner",
            "bedrock_guardrail_attached",
            "synthetic_content_provenance_tag",
        ],
        "expected_tier": "TRANSPARENCY_LIMITED",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-13-box-dimension-packer",
        "title": "Fulfillment Carton Box-Size Optimizer",
        "domain": "warehouse_logistics",
        "description": "Recommends corrugated box dimensions from item cubic volume and weight to reduce dunnage waste.",
        "jurisdictions": ["EU", "US"],
        "human_facing_genai": False,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": ["ai_bom_registration"],
        "expected_tier": "MINIMAL_RISK",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-14-ci-log-deduplicator",
        "title": "Internal CI Flaky-Test Failure Log Clusterer",
        "domain": "developer_productivity",
        "description": "Groups duplicate stack traces in internal build pipelines for SDE triage.",
        "jurisdictions": ["US"],
        "human_facing_genai": False,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": ["ai_bom_registration"],
        "expected_tier": "MINIMAL_RISK",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-15-catalog-taxonomy-classifier",
        "title": "Retail Browse-Node Product Category Classifier",
        "domain": "catalog_enrichment",
        "description": "Maps merchant item titles into standardized browse-node taxonomy IDs.",
        "jurisdictions": ["EU", "US", "JP"],
        "human_facing_genai": False,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": ["ai_bom_registration"],
        "expected_tier": "MINIMAL_RISK",
        "expected_verdict": "PASS_RELEASE",
    },
    {
        "system_id": "sys-16-unregistered-internal-tagger",
        "title": "Unregistered Internal Ticket Priority Tagger",
        "domain": "developer_productivity",
        "description": "Tags internal Jira/Sim engineering tickets by component without an AI-BOM entry.",
        "jurisdictions": ["US"],
        "human_facing_genai": False,
        "autonomous_decision": False,
        "prohibited_signals": [],
        "controls_present": [],
        "expected_tier": "MINIMAL_RISK",
        "expected_verdict": "BLOCK_MISSING_CONTROLS",
    },
]


def _infer_keyword_signals(description: str) -> Dict[str, Any]:
    low = (description or "").lower()
    inferred_prohibited: List[str] = []
    inferred_domain: Optional[str] = None

    if ("emotion" in low and ("workplace" in low or "employee" in low or "breakroom" in low or "school" in low)):
        inferred_prohibited.append("workplace_emotion_recognition")
    if "social scor" in low or "civic trustworthiness" in low:
        inferred_prohibited.append("social_scoring")
    if "subliminal" in low:
        inferred_prohibited.append("subliminal_manipulation")
    if "untargeted" in low and "facial" in low and "scrap" in low:
        inferred_prohibited.append("untargeted_facial_scraping")

    if any(k in low for k in ("resume", "applicant", "recruiting", "hiring", "candidate")):
        inferred_domain = "employment_hiring"
    elif any(k in low for k in ("creditworthiness", "loan", "underwrit", "lending")):
        inferred_domain = "credit_underwriting"
    elif any(k in low for k in ("medical triage", "patient", "clinical", "cardiopulmonary", "telehealth")):
        inferred_domain = "medical_triage"
    elif any(k in low for k in ("substation", "power grid", "microgrid", "breaker trip")):
        inferred_domain = "critical_infrastructure"
    elif any(k in low for k in ("biometric", "passport", "liveness", "selfie")):
        inferred_domain = "biometric_identification"

    return {"prohibited": inferred_prohibited, "high_risk_domain": inferred_domain}


def classify_ai_system_risk(
    manifest: Dict[str, Any],
    use_bedrock: bool = False,
) -> Dict[str, Any]:
    """Classify an AI workload under EU AI Act & NIST AI RMF and compute deterministic CI/CD release verdict."""
    t0 = time.perf_counter()
    system_id = str(manifest.get("system_id") or "custom-ai-system").strip()
    title = str(manifest.get("title") or system_id).strip()
    domain = str(manifest.get("domain") or "general").strip()
    description = str(manifest.get("description") or "").strip()
    jurisdictions = list(manifest.get("jurisdictions") or ["US", "EU"])
    human_facing_genai = bool(manifest.get("human_facing_genai", False))
    autonomous_decision = bool(manifest.get("autonomous_decision", False))
    prohibited_signals = list(manifest.get("prohibited_signals") or [])
    controls_present = sorted(set(str(c) for c in (manifest.get("controls_present") or [])))

    kw_signals = _infer_keyword_signals(description)
    all_prohibited = sorted(set(prohibited_signals + kw_signals["prohibited"]))
    effective_domain = domain if domain in HIGH_RISK_DOMAINS_MAP else (kw_signals["high_risk_domain"] or domain)

    # Stage 1: Deterministic Policy-as-Code classification
    if all_prohibited:
        det_tier = "PROHIBITED"
        eu_articles = [PROHIBITED_SIGNALS_MAP.get(sig, f"EU AI Act Art. 5 ({sig})") for sig in all_prohibited]
        nist_controls = ["GOVERN-1.1 (Unacceptable Risk Prohibition)", "MAP-1.6 (Decommission Order)"]
        rai_dimensions = ["Safety", "Fairness", "Privacy", "Governance", "Controllability"]
        det_confidence = 0.99
    elif effective_domain in HIGH_RISK_DOMAINS_MAP:
        det_tier = "HIGH_RISK"
        meta = HIGH_RISK_DOMAINS_MAP[effective_domain]
        eu_articles = [meta["eu_article"], "EU AI Act Art. 9-15 (Risk Mgmt, Data Governance, Annex IV Docs, Art. 14 Human Oversight)"]
        nist_controls = list(meta["nist_controls"])
        rai_dimensions = list(meta["rai_dimensions"])
        det_confidence = 0.96
    elif human_facing_genai or domain in ("customer_support_chatbot", "synthetic_media_generation"):
        det_tier = "TRANSPARENCY_LIMITED"
        eu_articles = ["EU AI Act Art. 50(1)-(2): Human-interaction AI disclosure & synthetic content provenance"]
        nist_controls = ["GOVERN-1.2", "MAP-2.2 (User Disclosure)", "MEASURE-2.8 (Hallucination & Guardrail Rate)"]
        rai_dimensions = ["Transparency", "Veracity", "Safety", "Privacy"]
        det_confidence = 0.94
    else:
        det_tier = "MINIMAL_RISK"
        eu_articles = ["EU AI Act Art. 95: Voluntary Codes of Conduct & Internal Inventory"]
        nist_controls = ["GOVERN-1.5 (Inventory Registration)", "MEASURE-2.1 (Operational Telemetry)"]
        rai_dimensions = ["Governance", "Robustness", "Security"]
        det_confidence = 0.95

    policy_eval_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    # Stage 2: Calibrated Amazon Bedrock semantic risk review (merged via zero-false-negative max severity lattice)
    fallback_bedrock = {
        "bedrock_tier": det_tier,
        "calibrated_confidence": det_confidence,
        "rationale": f"Classified '{title}' as {det_tier} based on domain '{effective_domain}' and jurisdictions {jurisdictions}.",
    }
    bedrock_out = invoke_bedrock_json(
        system_prompt=(
            "You are an EU AI Act & NIST AI RMF regulatory classification agent. "
            "Classify the AI system into exactly one of: PROHIBITED, HIGH_RISK, TRANSPARENCY_LIMITED, MINIMAL_RISK. "
            "Return JSON with keys: bedrock_tier (string), calibrated_confidence (float 0..1), rationale (2 sentences)."
        ),
        user_prompt=json.dumps(
            {
                "system_id": system_id,
                "title": title,
                "domain": domain,
                "description": description,
                "jurisdictions": jurisdictions,
                "human_facing_genai": human_facing_genai,
                "autonomous_decision": autonomous_decision,
                "prohibited_signals": all_prohibited,
            }
        ),
        fallback_payload=fallback_bedrock,
        use_bedrock=use_bedrock,
    )

    parsed_br = bedrock_out["parsed"]
    br_tier = str(parsed_br.get("bedrock_tier") or det_tier).upper().strip()
    if br_tier not in RISK_SEVERITY_ORDER:
        br_tier = det_tier

    # Safety lattice: never allow LLM output to downgrade a deterministic High-Risk or Prohibited finding
    final_tier = det_tier if RISK_SEVERITY_ORDER[det_tier] >= RISK_SEVERITY_ORDER[br_tier] else br_tier
    if final_tier == "HIGH_RISK" and det_tier != "HIGH_RISK":
        eu_articles = ["EU AI Act Art. 6(2) & Annex III: High-Risk Consequential Decision System (Escalated by Bedrock Classifier)"]
        nist_controls = ["GOVERN-1.2", "MAP-1.1", "MEASURE-2.11", "MANAGE-2.4"]
        rai_dimensions = ["Fairness", "Explainability", "Controllability", "Governance"]

    required_controls = REQUIRED_CONTROLS_BY_TIER[final_tier]
    if final_tier == "PROHIBITED":
        missing_controls = list(required_controls)
        release_verdict = "BLOCK_PROHIBITED_USE"
    else:
        missing_controls = [c for c in required_controls if c not in controls_present]
        release_verdict = "PASS_RELEASE" if not missing_controls else "BLOCK_MISSING_CONTROLS"

    try:
        conf_val = float(parsed_br.get("calibrated_confidence", det_confidence))
        conf_val = max(0.50, min(0.99, conf_val))
    except (TypeError, ValueError):
        conf_val = det_confidence

    model_card = {
        "card_version": "RAI-MODEL-CARD-v2.1",
        "system_id": system_id,
        "title": title,
        "effective_domain": effective_domain,
        "jurisdictions": jurisdictions,
        "eu_ai_act_tier": final_tier,
        "eu_ai_act_citations": eu_articles,
        "nist_ai_rmf_mappings": nist_controls,
        "amazon_rai_dimensions": rai_dimensions,
        "human_oversight_requirement": HUMAN_OVERSIGHT_BY_TIER[final_tier],
        "autonomous_decision_flag": autonomous_decision,
        "required_controls": required_controls,
        "verified_controls": [c for c in required_controls if c in controls_present],
        "missing_controls": missing_controls,
        "calibrated_confidence": round(conf_val, 3),
        "classifier_rationale": str(parsed_br.get("rationale") or fallback_bedrock["rationale"]),
    }

    return {
        "system_id": system_id,
        "title": title,
        "risk_tier": final_tier,
        "deterministic_tier": det_tier,
        "bedrock_tier": br_tier,
        "release_verdict": release_verdict,
        "required_controls": required_controls,
        "controls_present": controls_present,
        "missing_controls": missing_controls,
        "human_oversight_requirement": HUMAN_OVERSIGHT_BY_TIER[final_tier],
        "model_card": model_card,
        "policy_eval_ms": policy_eval_ms,
        "bedrock_latency_ms": bedrock_out["latency_ms"],
        "bedrock_tokens": bedrock_out["total_tokens"],
        "live_bedrock": bedrock_out["live_bedrock"],
        "llm_engine": bedrock_out["engine"],
    }


def evaluate_golden_risk_suite(use_bedrock_sample: bool = False) -> Dict[str, Any]:
    t0 = time.perf_counter()
    rows: List[Dict[str, Any]] = []
    tier_matches = 0
    verdict_matches = 0
    high_risk_total = 0
    high_risk_recalled = 0

    for idx, spec in enumerate(GOLDEN_RISK_SYSTEMS):
        res = classify_ai_system_risk(spec, use_bedrock=(use_bedrock_sample and idx in (0, 3, 9)))
        t_ok = res["risk_tier"] == spec["expected_tier"]
        v_ok = res["release_verdict"] == spec["expected_verdict"]
        if t_ok:
            tier_matches += 1
        if v_ok:
            verdict_matches += 1
        if spec["expected_tier"] in ("HIGH_RISK", "PROHIBITED"):
            high_risk_total += 1
            if res["risk_tier"] in ("HIGH_RISK", "PROHIBITED"):
                high_risk_recalled += 1
        rows.append(
            {
                "system_id": spec["system_id"],
                "title": spec["title"],
                "expected_tier": spec["expected_tier"],
                "predicted_tier": res["risk_tier"],
                "expected_verdict": spec["expected_verdict"],
                "release_verdict": res["release_verdict"],
                "missing_controls_count": len(res["missing_controls"]),
                "policy_eval_ms": res["policy_eval_ms"],
                "bedrock_latency_ms": res["bedrock_latency_ms"],
                "bedrock_tokens": res["bedrock_tokens"],
                "matched": t_ok and v_ok,
            }
        )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    n = len(GOLDEN_RISK_SYSTEMS)
    return {
        "systems_evaluated": n,
        "tier_accuracy_pct": round((tier_matches / n) * 100.0, 1),
        "verdict_accuracy_pct": round((verdict_matches / n) * 100.0, 1),
        "high_risk_and_prohibited_recall_pct": round((high_risk_recalled / max(1, high_risk_total)) * 100.0, 1),
        "total_eval_ms": elapsed_ms,
        "results": rows,
    }
