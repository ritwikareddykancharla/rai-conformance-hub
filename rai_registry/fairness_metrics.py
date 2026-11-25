"""Subgroup Fairness Engine: Confusion Matrices, 4/5ths Disparate Impact, Equalized Odds, ECE & Threshold Mitigator."""
from __future__ import annotations

import math
import random
import time
from typing import Any, Dict, List, Optional, Tuple

FAIRNESS_SCENARIO_SPECS: Dict[str, Dict[str, Any]] = {
    "resume_screening_v2": {
        "scenario_id": "resume_screening_v2",
        "title": "Automated Technical Resume Screener (4,000 Applicants Across 4 Subgroups)",
        "eu_annex": "EU AI Act Annex III §4(a) · Employment & Candidate Selection",
        "reference_group": "Cohort_A_Standard",
        "groups": [
            {"name": "Cohort_A_Standard", "count": 1200, "base_pos_rate": 0.46, "pos_mu": 0.69, "neg_mu": 0.34, "sigma": 0.14},
            {"name": "Cohort_B_CareerBreak", "count": 1000, "base_pos_rate": 0.45, "pos_mu": 0.56, "neg_mu": 0.27, "sigma": 0.14},
            {"name": "Cohort_C_NonTradEdu", "count": 1000, "base_pos_rate": 0.44, "pos_mu": 0.55, "neg_mu": 0.26, "sigma": 0.14},
            {"name": "Cohort_D_RegionalIntl", "count": 800, "base_pos_rate": 0.45, "pos_mu": 0.62, "neg_mu": 0.30, "sigma": 0.14},
        ],
        "seed": 20261125,
    },
    "seller_credit_underwriting": {
        "scenario_id": "seller_credit_underwriting",
        "title": "Small-Merchant Working-Capital Loan Underwriter (4,000 Applications)",
        "eu_annex": "EU AI Act Annex III §5(b) · Creditworthiness Assessment",
        "reference_group": "Established_Metro_Sellers",
        "groups": [
            {"name": "Established_Metro_Sellers", "count": 1300, "base_pos_rate": 0.52, "pos_mu": 0.71, "neg_mu": 0.35, "sigma": 0.14},
            {"name": "Rural_Micro_Merchants", "count": 1000, "base_pos_rate": 0.50, "pos_mu": 0.57, "neg_mu": 0.27, "sigma": 0.14},
            {"name": "New_Sole_Proprietors", "count": 900, "base_pos_rate": 0.49, "pos_mu": 0.56, "neg_mu": 0.26, "sigma": 0.14},
            {"name": "CrossBorder_Artisans", "count": 800, "base_pos_rate": 0.51, "pos_mu": 0.63, "neg_mu": 0.30, "sigma": 0.14},
        ],
        "seed": 20261126,
    },
    "customer_fraud_freeze": {
        "scenario_id": "customer_fraud_freeze",
        "title": "Buyer Return Legitimacy & Good-Standing Classifier (4,000 Claims)",
        "eu_annex": "Amazon RAI Fairness & Consumer Access Standard",
        "reference_group": "Prime_Tenure_5yr",
        "groups": [
            {"name": "Prime_Tenure_5yr", "count": 1200, "base_pos_rate": 0.60, "pos_mu": 0.72, "neg_mu": 0.34, "sigma": 0.13},
            {"name": "Prepaid_Card_Users", "count": 1000, "base_pos_rate": 0.58, "pos_mu": 0.56, "neg_mu": 0.26, "sigma": 0.14},
            {"name": "Multi_Household_Addr", "count": 1000, "base_pos_rate": 0.59, "pos_mu": 0.58, "neg_mu": 0.27, "sigma": 0.14},
            {"name": "Mobile_Only_NewUsers", "count": 800, "base_pos_rate": 0.58, "pos_mu": 0.61, "neg_mu": 0.29, "sigma": 0.13},
        ],
        "seed": 20261127,
    },
}


def generate_subgroup_dataset(scenario_id: str = "resume_screening_v2") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Generate a deterministic 4,000-row subgroup scoring dataset exhibiting realistic uncalibrated threshold bias."""
    spec = FAIRNESS_SCENARIO_SPECS.get(scenario_id) or FAIRNESS_SCENARIO_SPECS["resume_screening_v2"]
    rng = random.Random(int(spec["seed"]))
    records: List[Dict[str, Any]] = []

    for g in spec["groups"]:
        g_name = g["name"]
        n = int(g["count"])
        pos_rate = float(g["base_pos_rate"])
        pos_mu = float(g["pos_mu"])
        neg_mu = float(g["neg_mu"])
        sigma = float(g["sigma"])

        for _ in range(n):
            y_true = 1 if rng.random() < pos_rate else 0
            mu = pos_mu if y_true == 1 else neg_mu
            raw = rng.gauss(mu, sigma)
            score = max(0.01, min(0.99, round(raw, 4)))
            records.append({"group": g_name, "y_true": y_true, "y_score": score})

    return records, spec


def compute_expected_calibration_error(records: List[Dict[str, Any]], num_bins: int = 10) -> float:
    """Compute 10-bin Expected Calibration Error (ECE) on probability scores."""
    if not records:
        return 0.0
    bins: List[List[Tuple[int, float]]] = [[] for _ in range(num_bins)]
    for r in records:
        s = max(0.0, min(1.0, float(r["y_score"])))
        idx = min(num_bins - 1, int(s * num_bins))
        bins[idx].append((int(r["y_true"]), s))

    total = len(records)
    ece = 0.0
    for b in bins:
        if not b:
            continue
        avg_acc = sum(y for y, _ in b) / len(b)
        avg_conf = sum(s for _, s in b) / len(b)
        ece += (len(b) / total) * abs(avg_acc - avg_conf)
    return round(ece, 4)


def evaluate_thresholds(
    records: List[Dict[str, Any]],
    group_thresholds: Dict[str, float],
    reference_group: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute exact subgroup confusion matrices, Disparate Impact (4/5ths rule), |ΔTPR|, |ΔFPR|, F1, and ECE."""
    by_group: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        by_group.setdefault(str(r["group"]), []).append(r)

    group_names = sorted(by_group.keys())
    if not group_names:
        raise ValueError("Dataset contains zero subgroup records")

    subgroup_metrics: Dict[str, Dict[str, Any]] = {}
    total_tp = total_fp = total_tn = total_fn = 0

    for g in group_names:
        rows = by_group[g]
        tau = float(group_thresholds.get(g, 0.50))
        tp = fp = tn = fn = 0
        for r in rows:
            y_t = int(r["y_true"])
            y_p = 1 if float(r["y_score"]) >= tau else 0
            if y_t == 1 and y_p == 1:
                tp += 1
            elif y_t == 0 and y_p == 1:
                fp += 1
            elif y_t == 0 and y_p == 0:
                tn += 1
            else:
                fn += 1

        total_tp += tp
        total_fp += fp
        total_tn += tn
        total_fn += fn

        n = len(rows)
        sel_rate = (tp + fp) / max(1, n)
        tpr = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        ppv = tp / max(1, tp + fp)
        f1 = (2.0 * tp) / max(1, 2 * tp + fp + fn)
        g_ece = compute_expected_calibration_error(rows)

        subgroup_metrics[g] = {
            "group": g,
            "count": n,
            "threshold": round(tau, 3),
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
            "selection_rate": round(sel_rate, 4),
            "TPR": round(tpr, 4),
            "FPR": round(fpr, 4),
            "precision": round(ppv, 4),
            "f1": round(f1, 4),
            "ece": g_ece,
        }

    # Reference group is either explicit or highest selection-rate subgroup
    ref_g = reference_group if (reference_group and reference_group in subgroup_metrics) else max(
        group_names, key=lambda name: subgroup_metrics[name]["selection_rate"]
    )
    ref_sel = max(1e-6, subgroup_metrics[ref_g]["selection_rate"])
    max_sel = max(m["selection_rate"] for m in subgroup_metrics.values())
    min_sel = min(m["selection_rate"] for m in subgroup_metrics.values())

    # Disparate impact ratio relative to reference group (and worst-case pairwise min/max ratio)
    di_vs_ref = min(m["selection_rate"] / ref_sel for m in subgroup_metrics.values())
    di_min_max = min_sel / max(1e-6, max_sel)
    disparate_impact_ratio = round(min(di_vs_ref, di_min_max), 4)

    for g, m in subgroup_metrics.items():
        m["disparate_impact_vs_ref"] = round(m["selection_rate"] / ref_sel, 4)

    dp_diff = round(max_sel - min_sel, 4)
    tprs = [m["TPR"] for m in subgroup_metrics.values()]
    fprs = [m["FPR"] for m in subgroup_metrics.values()]
    delta_tpr = round(max(tprs) - min(tprs), 4)
    delta_fpr = round(max(fprs) - min(fprs), 4)
    eq_odds_gap = round(max(delta_tpr, delta_fpr), 4)

    overall_f1 = round((2.0 * total_tp) / max(1, 2 * total_tp + total_fp + total_fn), 4)
    overall_acc = round((total_tp + total_tn) / max(1, len(records)), 4)
    overall_ece = compute_expected_calibration_error(records)

    passes_four_fifths = disparate_impact_ratio >= 0.80
    passes_eq_opportunity = delta_tpr <= 0.06
    passes_eq_odds = eq_odds_gap <= 0.08
    compliant = passes_four_fifths and passes_eq_opportunity and passes_eq_odds

    return {
        "reference_group": ref_g,
        "total_records": len(records),
        "overall_f1": overall_f1,
        "overall_accuracy": overall_acc,
        "overall_ece": overall_ece,
        "demographic_parity_diff": dp_diff,
        "disparate_impact_ratio": disparate_impact_ratio,
        "passes_four_fifths_rule": passes_four_fifths,
        "equal_opportunity_diff_tpr": delta_tpr,
        "false_positive_diff_fpr": delta_fpr,
        "equalized_odds_max_gap": eq_odds_gap,
        "fairness_verdict": "PASS_FAIRNESS" if compliant else "FAIL_FAIRNESS_VIOLATION",
        "subgroups": [subgroup_metrics[g] for g in group_names],
    }


def optimize_group_thresholds(
    records: List[Dict[str, Any]],
    reference_group: Optional[str] = None,
    base_threshold: float = 0.50,
) -> Dict[str, float]:
    """Post-processing group-threshold optimizer restoring 4/5ths DI >= 0.85 and Equal Opportunity with minimal F1 loss."""
    by_group: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        by_group.setdefault(str(r["group"]), []).append(r)

    group_names = sorted(by_group.keys())
    ref_g = reference_group if (reference_group and reference_group in by_group) else group_names[0]

    # Pre-sort scores per subgroup for fast threshold grid search across [0.25, 0.75]
    candidate_taus = [round(0.24 + 0.01 * i, 2) for i in range(52)]

    def _stats_at_tau(rows: List[Dict[str, Any]], tau: float) -> Dict[str, float]:
        tp = fp = tn = fn = 0
        for r in rows:
            yt = int(r["y_true"])
            yp = 1 if float(r["y_score"]) >= tau else 0
            if yt == 1 and yp == 1:
                tp += 1
            elif yt == 0 and yp == 1:
                fp += 1
            elif yt == 0 and yp == 0:
                tn += 1
            else:
                fn += 1
        n = max(1, len(rows))
        return {
            "sel": (tp + fp) / n,
            "tpr": tp / max(1, tp + fn),
            "fpr": fp / max(1, fp + tn),
            "f1": (2.0 * tp) / max(1, 2 * tp + fp + fn),
        }

    # Anchor reference group near base_threshold across [base-0.06, base+0.08]
    ref_candidates = [round(base_threshold + 0.02 * d, 2) for d in range(-3, 5)]
    best_global_score = -1e9
    best_thresholds = {g: base_threshold for g in group_names}

    precomputed: Dict[str, Dict[float, Dict[str, float]]] = {
        g: {tau: _stats_at_tau(by_group[g], tau) for tau in candidate_taus} for g in group_names
    }

    for ref_tau in ref_candidates:
        if ref_tau not in precomputed[ref_g]:
            continue
        ref_st = precomputed[ref_g][ref_tau]
        chosen: Dict[str, float] = {ref_g: ref_tau}

        for g in group_names:
            if g == ref_g:
                continue
            best_g_tau = base_threshold
            best_g_obj = -1e9
            for tau in candidate_taus:
                st = precomputed[g][tau]
                ratio = min(st["sel"], ref_st["sel"]) / max(1e-6, max(st["sel"], ref_st["sel"]))
                tpr_gap = abs(st["tpr"] - ref_st["tpr"])
                fpr_gap = abs(st["fpr"] - ref_st["fpr"])
                # Strongly reward feasibility (DI >= 0.86, pairwise |ΔTPR| <= 0.05, |ΔFPR| <= 0.06) while maximizing subgroup F1
                penalty = 0.0
                if ratio < 0.86:
                    penalty += (0.86 - ratio) * 18.0
                if tpr_gap > 0.024:
                    penalty += (tpr_gap - 0.024) * 28.0
                if fpr_gap > 0.028:
                    penalty += (fpr_gap - 0.028) * 26.0
                obj = st["f1"] - penalty - 0.20 * tpr_gap - 0.10 * (1.0 - ratio)
                if obj > best_g_obj:
                    best_g_obj = obj
                    best_g_tau = tau
            chosen[g] = best_g_tau

        eval_res = evaluate_thresholds(records, chosen, reference_group=ref_g)
        feasible_bonus = 10.0 if eval_res["fairness_verdict"] == "PASS_FAIRNESS" else 0.0
        global_score = (
            feasible_bonus
            + eval_res["overall_f1"]
            - 0.3 * eval_res["equalized_odds_max_gap"]
            + 0.1 * eval_res["disparate_impact_ratio"]
        )
        if global_score > best_global_score:
            best_global_score = global_score
            best_thresholds = chosen

    return best_thresholds


def run_fairness_audit(
    scenario_id: str = "resume_screening_v2",
    base_threshold: float = 0.50,
    mitigate: bool = True,
    custom_records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Run full pre-mitigation audit + post-processing group threshold optimization."""
    t0 = time.perf_counter()
    if custom_records is not None:
        records = custom_records
        spec = {
            "scenario_id": scenario_id or "custom_audit",
            "title": "Custom Subgroup Decision Log Audit",
            "eu_annex": "EU AI Act Art. 10 & NIST AI RMF MEASURE 2.11",
            "reference_group": None,
        }
    else:
        records, spec = generate_subgroup_dataset(scenario_id)

    groups = sorted({str(r["group"]) for r in records})
    uniform_thresholds = {g: float(base_threshold) for g in groups}
    baseline = evaluate_thresholds(records, uniform_thresholds, reference_group=spec.get("reference_group"))

    mitigated: Optional[Dict[str, Any]] = None
    recommended_thresholds = uniform_thresholds
    if mitigate:
        recommended_thresholds = optimize_group_thresholds(
            records,
            reference_group=baseline["reference_group"],
            base_threshold=float(base_threshold),
        )
        mitigated = evaluate_thresholds(
            records,
            recommended_thresholds,
            reference_group=baseline["reference_group"],
        )

    audit_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    f1_delta = round((mitigated["overall_f1"] - baseline["overall_f1"]), 4) if mitigated else 0.0

    return {
        "scenario_id": spec["scenario_id"],
        "title": spec["title"],
        "regulatory_scope": spec["eu_annex"],
        "rows_evaluated": len(records),
        "base_threshold": round(float(base_threshold), 3),
        "baseline_metrics": baseline,
        "mitigation_applied": mitigate,
        "recommended_group_thresholds": recommended_thresholds,
        "mitigated_metrics": mitigated,
        "f1_tradeoff_delta": f1_delta,
        "final_verdict": mitigated["fairness_verdict"] if mitigated else baseline["fairness_verdict"],
        "audit_ms": audit_ms,
    }
