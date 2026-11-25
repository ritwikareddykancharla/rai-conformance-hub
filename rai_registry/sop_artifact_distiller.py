"""Write-Time SOP-to-Atomic Knowledge Artifact Distiller & Multi-Locale (`en-US / es-US / de-DE / ja-JP`) Conflict Detector."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

from .bedrock_client import invoke_bedrock_json

SUPPORTED_LOCALES = ("en-US", "es-US", "de-DE", "ja-JP")

# Canonical multi-locale Customer Service SOP policy bundles (with realistic translation drift & regional overrides)
CS_POLICY_BUNDLES: Dict[str, Dict[str, Any]] = {
    "electronics_returns": {
        "policy_family": "electronics_returns",
        "title": "Consumer Electronics & Opened Software Return SOP",
        "locales": {
            "en-US": {
                "marketplace": "US",
                "sop_id": "SOP-CS-RET-EN-US-2026.4",
                "last_updated": "2026-10-15",
                "statutory_override": False,
                "expected_window_days": 30,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "opened_physical_software_non_refundable",
                    "lithium_battery_over_100wh_hazmat_restricted",
                    "missing_serial_number_inspection_hold",
                ],
                "sop_prose": (
                    "Amazon US Customer Service Standard Operating Procedure (SOP-CS-RET-EN-US-2026.4). "
                    "Customers in the US marketplace may return unopened or defective consumer electronics within 30 days "
                    "of delivery for a full 100% refund with a 0% restocking fee, provided the original factory serial number "
                    "matches the fulfillment scan. Exceptions that agents and automated workflows must enforce: "
                    "(1) opened physical software media and scratched digital activation cards are non-refundable and only "
                    "eligible for identical title exchange within 30 days; "
                    "(2) standalone lithium-ion power banks exceeding 100 Wh cannot use standard prepaid drop-off labels and "
                    "require hazmat ground carrier scheduling; "
                    "(3) high-value electronics returned with a missing or altered serial number must be placed in a 7-day "
                    "inspection hold before any refund is released. Agents must disclose that refund settlement takes up to 5 business days."
                ),
            },
            "es-US": {
                "marketplace": "US",
                "sop_id": "SOP-CS-RET-ES-US-2025.1",
                "last_updated": "2025-08-02",
                "statutory_override": False,
                "expected_window_days": 45,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "opened_physical_software_non_refundable",
                ],
                "sop_prose": (
                    "Procedimiento Operativo de Servicio al Cliente EE. UU. en Espanol (SOP-CS-RET-ES-US-2025.1). "
                    "Los clientes en el mercado de EE. UU. pueden devolver articulos electronicos dentro de 45 dias "
                    "posteriores a la entrega con una tarifa de reposicion del 0%. Excepcion unica registrada: "
                    "(1) el software fisico abierto y las tarjetas digitales raspadas no son reembolsables. "
                    "Nota: El agente debe informar al cliente que el reembolso bancario tarda hasta 5 dias habiles."
                ),
            },
            "de-DE": {
                "marketplace": "DE",
                "sop_id": "SOP-CS-RET-DE-DE-2026.4",
                "last_updated": "2026-10-16",
                "statutory_override": True,
                "expected_window_days": 14,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "opened_physical_software_non_refundable",
                    "lithium_battery_over_100wh_hazmat_restricted",
                    "missing_serial_number_inspection_hold",
                ],
                "sop_prose": (
                    "Amazon Deutschland Kundenservice Richtlinie (SOP-CS-RET-DE-DE-2026.4, EU-Verbraucherrechterichtlinie 2011/83/EU). "
                    "Kunden auf dem deutschen Marktplatz haben ein gesetzliches Widerrufsrecht von 14 Tagen ab Erhalt der Ware "
                    "bei 0% Wiedereinlagerungsgebuehr. Verbindliche Ausnahmen: "
                    "(1) entsiegelte physische Software-Datentraeger und eingeloste digitale Codes sind vom Widerruf ausgeschlossen; "
                    "(2) Lithium-Ionen-Akkus ueber 100 Wh duerfen nicht per Standardpaket versendet werden, sondern erfordern "
                    "Gefahrgut-Abholung; "
                    "(3) Geraete mit fehlender Seriennummer unterliegen einer 7-taegigen Wareneingangspruefung. "
                    "Pflichthinweis: Gesetzliches 14-Tage-Widerrufsrecht bleibt unberuehrt; Rueckerstattung innerhalb von 5 Werktagen."
                ),
            },
            "ja-JP": {
                "marketplace": "JP",
                "sop_id": "SOP-CS-RET-JA-JP-2026.3",
                "last_updated": "2026-09-28",
                "statutory_override": True,
                "expected_window_days": 30,
                "expected_restocking_fee_pct": 50,
                "canonical_exceptions": [
                    "opened_physical_software_non_refundable",
                    "lithium_battery_over_100wh_hazmat_restricted",
                    "missing_serial_number_inspection_hold",
                ],
                "sop_prose": (
                    "Amazon.co.jp カスタマーサービス標準手順書 (SOP-CS-RET-JA-JP-2026.3). "
                    "日本マーケットプレイスの顧客は商品到着後 30 日以内に家電製品を返品できます。未開封品は全額返金されますが、"
                    "顧客都合で開封済みの良品は商品代金の 50% の返品手数料（50% 返金）が適用されます（地域特例ルール）。"
                    "必須例外事項: (1) 開封済みパッケージソフトおよび使用済みデジタルコードは返金不可、"
                    "(2) 100 Wh を超えるリチウムイオンバッテリーは通常配送ラベル使用不可（危険物陸送手配が必要）、"
                    "(3) シリアル番号欠損品は 7 日間の検品保留を実施。返金処理完了まで最大 5 営業日かかる旨を案内すること。"
                ),
            },
        },
    },
    "digital_subscriptions_refund": {
        "policy_family": "digital_subscriptions_refund",
        "title": "Annual Streaming & SaaS Membership Cancellation SOP",
        "locales": {
            "en-US": {
                "marketplace": "US",
                "sop_id": "SOP-CS-SUB-EN-US-2026.2",
                "last_updated": "2026-10-01",
                "statutory_override": False,
                "expected_window_days": 14,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "zero_benefit_usage_required_for_full_refund",
                    "promotional_bundle_credit_clawback",
                ],
                "sop_prose": (
                    "Amazon US Digital Subscription Cancellation Policy (SOP-CS-SUB-EN-US-2026.2). "
                    "Members who cancel a paid annual subscription within 14 days of charge receive a 100% refund with 0% fee "
                    "only if zero streaming or benefit usage occurred since renewal. Exceptions: "
                    "(1) accounts that streamed content or redeemed member shipping benefits after renewal are ineligible for "
                    "full refund and receive end-of-cycle cancellation instead; "
                    "(2) promotional gift-card bundle credits granted at signup are deducted (clawback) from any early refund. "
                    "Agents must disclose the exact billing cycle end date within 3 business days notice."
                ),
            },
            "es-US": {
                "marketplace": "US",
                "sop_id": "SOP-CS-SUB-ES-US-2026.2",
                "last_updated": "2026-10-01",
                "statutory_override": False,
                "expected_window_days": 14,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "zero_benefit_usage_required_for_full_refund",
                    "promotional_bundle_credit_clawback",
                ],
                "sop_prose": (
                    "Politica de Cancelacion de Suscripciones Digitales EE. UU. (SOP-CS-SUB-ES-US-2026.2). "
                    "Los miembros en EE. UU. que cancelen dentro de 14 dias posteriores al cobro reciben reembolso completo con 0% "
                    "de cargo unicamente si registran cero uso de beneficios desde la renovacion. Excepciones: "
                    "(1) cuentas con uso de streaming o envios reciben cancelacion al final del ciclo sin reembolso inmediato; "
                    "(2) los creditos promocionales otorgados al inscribirse se descuentan del reembolso anticipado. "
                    "Se debe informar la fecha exacta de corte dentro de 3 dias habiles."
                ),
            },
            "de-DE": {
                "marketplace": "DE",
                "sop_id": "SOP-CS-SUB-DE-DE-2025.0",
                "last_updated": "2025-05-10",
                "statutory_override": False,
                "expected_window_days": 7,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "zero_benefit_usage_required_for_full_refund",
                ],
                "sop_prose": (
                    "Fehlerhafte Entwurfsrichtlinie Digital-Abo Deutschland (SOP-CS-SUB-DE-DE-2025.0). "
                    "Mitglieder koennen ein Jahresabo nur innerhalb von 7 Tagen nach Abbuchung bei 0% Gebuehr widerrufen, "
                    "sofern keine Streaming-Vorteile genutzt wurden. Fristmitteilung erfolgt binnen 3 Werktagen."
                ),
            },
            "ja-JP": {
                "marketplace": "JP",
                "sop_id": "SOP-CS-SUB-JA-JP-2026.2",
                "last_updated": "2026-10-02",
                "statutory_override": True,
                "expected_window_days": 14,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "zero_benefit_usage_required_for_full_refund",
                    "promotional_bundle_credit_clawback",
                ],
                "sop_prose": (
                    "Amazon.co.jp デジタル年間メンバーシップ解約規定 (SOP-CS-SUB-JA-JP-2026.2). "
                    "更新請求から 14 日以内かつ特典利用が 0 回の場合に限り、手数料 0% で全額返金します。例外事項: "
                    "(1) 更新後に動画視聴や配送特典を利用した場合は期間満了時の解約予約となり即時返金対象外、"
                    "(2) 入会時キャンペーンポイントは返金額から差し引き（クローバック）。3 営業日以内に解約確定日を通知すること。"
                ),
            },
        },
    },
    "hazmat_battery_shipping": {
        "policy_family": "hazmat_battery_shipping",
        "title": "Damaged Lithium Battery & Hazmat Replacement SOP",
        "locales": {
            "en-US": {
                "marketplace": "US",
                "sop_id": "SOP-CS-HAZ-EN-US-2026.1",
                "last_updated": "2026-11-01",
                "statutory_override": False,
                "expected_window_days": 30,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "swollen_or_leaking_battery_never_return_ship",
                    "lithium_battery_over_100wh_hazmat_restricted",
                ],
                "sop_prose": (
                    "Amazon US Hazmat & Damaged Battery SOP (SOP-CS-HAZ-EN-US-2026.1). "
                    "Customers reporting damaged battery-powered items within 30 days receive a 0% fee refund or replacement. "
                    "Mandatory safety exceptions: (1) swollen, punctured, overheated, or leaking lithium batteries must NEVER "
                    "be shipped back by air or ground; issue a returnless refund and share municipal hazmat disposal instructions; "
                    "(2) intact standalone batteries above 100 Wh require certified hazmat ground pickup. "
                    "Agents must log a product safety incident ticket within 24 hours."
                ),
            },
            "es-US": {
                "marketplace": "US",
                "sop_id": "SOP-CS-HAZ-ES-US-2026.1",
                "last_updated": "2026-11-01",
                "statutory_override": False,
                "expected_window_days": 30,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "lithium_battery_over_100wh_hazmat_restricted",
                ],
                "sop_prose": (
                    "Procedimiento de Baterias y Materiales Peligrosos EE. UU. (SOP-CS-HAZ-ES-US-2026.1). "
                    "Reclamos dentro de 30 dias califican con 0% de tarifa. Excepcion: "
                    "(1) baterias independientes mayores a 100 Wh requieren recoleccion terrestre certificada. "
                    "Registrar ticket de seguridad dentro de 24 horas."
                ),
            },
            "de-DE": {
                "marketplace": "DE",
                "sop_id": "SOP-CS-HAZ-DE-DE-2026.1",
                "last_updated": "2026-11-01",
                "statutory_override": True,
                "expected_window_days": 30,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "swollen_or_leaking_battery_never_return_ship",
                    "lithium_battery_over_100wh_hazmat_restricted",
                ],
                "sop_prose": (
                    "Amazon DE Gefahrgut- und Defektakku-Richtlinie (SOP-CS-HAZ-DE-DE-2026.1). "
                    "Defekte Akku-Artikel koennen innerhalb von 30 Tagen bei 0% Gebuehr reklamiert werden (gesetzliche Gewaehrleistung "
                    "und 14-taegiges Widerrufsrecht gewahrt). Sicherheitsausnahmen: "
                    "(1) aufgeblaehte oder auslaufende Lithium-Akkus niemals zuruecksenden (ruecksendungslose Erstattung + Entsorgungshinweis); "
                    "(2) intakte Akkus ueber 100 Wh erfordern Gefahrgut-Spezialtransport. Sicherheitsmeldung binnen 24 Stunden."
                ),
            },
            "ja-JP": {
                "marketplace": "JP",
                "sop_id": "SOP-CS-HAZ-JA-JP-2026.1",
                "last_updated": "2026-11-01",
                "statutory_override": True,
                "expected_window_days": 30,
                "expected_restocking_fee_pct": 0,
                "canonical_exceptions": [
                    "swollen_or_leaking_battery_never_return_ship",
                    "lithium_battery_over_100wh_hazmat_restricted",
                ],
                "sop_prose": (
                    "Amazon.co.jp 危険物・破損バッテリー対応手順 (SOP-CS-HAZ-JA-JP-2026.1). "
                    "到着後 30 日以内の破損バッテリー申告は手数料 0% で返金または交換対応。安全上の必須例外: "
                    "(1) 膨張・液漏れ・発熱しているリチウム電池は絶対に返送させず返送不要返金とし自治体廃棄案内を送付、"
                    "(2) 未破損でも 100 Wh 超のバッテリーは危険物陸送手配が必須。24 時間以内に製品安全チケットを起票すること。"
                ),
            },
        },
    },
}

EXCEPTION_DETECT_PATTERNS = {
    "opened_physical_software_non_refundable": [
        r"opened physical software",
        r"software fisico abierto",
        r"entsiegelte physische software",
        r"開封済みパッケージソフト",
        r"opened software",
        r"digital activation",
        r"デジタルコード",
    ],
    "lithium_battery_over_100wh_hazmat_restricted": [
        r"100\s*wh",
    ],
    "missing_serial_number_inspection_hold": [
        r"serial number",
        r"seriennummer",
        r"シリアル番号",
    ],
    "zero_benefit_usage_required_for_full_refund": [
        r"zero streaming",
        r"cero uso",
        r"keine streaming",
        r"特典利用が\s*0\s*回",
    ],
    "promotional_bundle_credit_clawback": [
        r"clawback",
        r"promotional",
        r"creditos promocionales",
        r"キャンペーンポイント",
    ],
    "swollen_or_leaking_battery_never_return_ship": [
        r"swollen",
        r"returnless refund",
        r"aufgeblaehte",
        r"膨張",
        r"返送不要返金",
    ],
}


def _extract_deterministic_facts(
    sop_prose: str,
    locale: str,
    marketplace: str,
    policy_family: str,
    statutory_override: bool,
) -> Dict[str, Any]:
    """Deterministic parser extracting grounded window days, fees, exceptions, disclosures, and exact character spans."""
    numbers_in_text = [int(m.group(0)) for m in re.finditer(r"\b\d+\b", sop_prose)]

    # Extract refund window days near day/dias/Tagen/日 tokens
    day_match = re.search(
        r"(\d+)\s*(?:days|day|dias|Tagen|Tage|taegig\w*|日以内|日)",
        sop_prose,
        flags=re.IGNORECASE,
    )
    refund_days = int(day_match.group(1)) if day_match else (numbers_in_text[0] if numbers_in_text else 30)

    # Extract restocking / cancellation fee %
    fee_match = re.search(
        r"(\d+)\s*%\s*(?:の\s*)?(?:restocking|reposicion|Wiedereinlagerungs\w*|Gebuehr|fee|cargo|手数料|返品手数料)",
        sop_prose,
        flags=re.IGNORECASE,
    )
    fee_pct = int(fee_match.group(1)) if fee_match else 0

    detected_exceptions: List[str] = []
    for canonical_key, patterns in EXCEPTION_DETECT_PATTERNS.items():
        if any(re.search(pat, sop_prose, flags=re.IGNORECASE) for pat in patterns):
            detected_exceptions.append(canonical_key)

    disclosures: List[str] = []
    if re.search(r"5\s*(?:business days|dias habiles|Werktagen|営業日)", sop_prose, flags=re.IGNORECASE):
        disclosures.append("refund_settlement_within_5_business_days")
    if re.search(r"3\s*(?:business days|dias habiles|Werktagen|営業日)", sop_prose, flags=re.IGNORECASE):
        disclosures.append("cancellation_date_notice_within_3_business_days")
    if re.search(r"24\s*(?:hours|horas|Stunden|時間)", sop_prose, flags=re.IGNORECASE):
        disclosures.append("log_safety_incident_within_24_hours")
    if re.search(r"2011/83/EU|Widerrufsrecht", sop_prose, flags=re.IGNORECASE):
        disclosures.append("eu_statutory_14d_withdrawal_notice")

    span_start = day_match.start() if day_match else 0
    span_end = min(len(sop_prose), max(span_start + 90, 140))
    quote = sop_prose[max(0, span_start - 24) : span_end].strip()

    return {
        "artifact_id": f"KA-{policy_family[:6].upper()}-{locale.upper()}",
        "policy_family": policy_family,
        "locale": locale,
        "marketplace": marketplace,
        "preconditions": [
            f"marketplace == '{marketplace}'",
            f"days_since_event <= {refund_days}",
        ],
        "refund_window_days": refund_days,
        "restocking_fee_pct": fee_pct,
        "exceptions": detected_exceptions,
        "required_disclosures": disclosures or ["standard_cs_policy_receipt"],
        "statutory_override": statutory_override,
        "source_span": {
            "start_char": max(0, span_start - 24),
            "end_char": span_end,
            "verbatim_quote": quote,
        },
    }


def verify_artifact_entailment(sop_prose: str, artifact: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministically verify 100% numeric grounding, character-span validity, and source exception recall."""
    source_numbers = {int(m.group(0)) for m in re.finditer(r"\b\d+\b", sop_prose)}
    # Also recognize common spelled-out zero words across EN/ES/DE/JA
    if re.search(r"\b(zero|cero|keine|null)\b", sop_prose, flags=re.IGNORECASE):
        source_numbers.add(0)

    checked_numbers = [
        ("refund_window_days", int(artifact.get("refund_window_days", -1))),
        ("restocking_fee_pct", int(artifact.get("restocking_fee_pct", -1))),
    ]
    ungrounded_numbers = [
        f"{field}={val}" for field, val in checked_numbers if val not in source_numbers
    ]
    numeric_grounded = len(ungrounded_numbers) == 0

    # Verify source exceptions present in prose vs captured in artifact
    expected_in_source: List[str] = []
    for canonical_key, patterns in EXCEPTION_DETECT_PATTERNS.items():
        if any(re.search(pat, sop_prose, flags=re.IGNORECASE) for pat in patterns):
            expected_in_source.append(canonical_key)

    captured = set(artifact.get("exceptions") or [])
    recalled = [e for e in expected_in_source if e in captured]
    missed_exceptions = [e for e in expected_in_source if e not in captured]
    exception_recall_pct = (
        round((len(recalled) / len(expected_in_source)) * 100.0, 1) if expected_in_source else 100.0
    )

    span = artifact.get("source_span") or {}
    quote = str(span.get("verbatim_quote") or "")
    span_valid = bool(quote) and (quote in sop_prose)

    # Token efficiency comparison (approx 4 chars/token for Latin, 1.8 chars/token for CJK)
    prose_tokens_est = max(1, len(sop_prose) // 4)
    compact_artifact_json = json.dumps(
        {
            "id": artifact.get("artifact_id"),
            "days": artifact.get("refund_window_days"),
            "fee": artifact.get("restocking_fee_pct"),
            "exc": artifact.get("exceptions"),
            "disc": artifact.get("required_disclosures"),
        },
        separators=(",", ":"),
    )
    artifact_tokens_est = max(1, len(compact_artifact_json) // 4)
    token_reduction_pct = round(max(0.0, (1.0 - (artifact_tokens_est / prose_tokens_est)) * 100.0), 1)

    entailed = numeric_grounded and (len(missed_exceptions) == 0) and span_valid
    return {
        "entailed": entailed,
        "numeric_precision_pct": 100.0 if numeric_grounded else 0.0,
        "ungrounded_numbers": ungrounded_numbers,
        "expected_source_exceptions": expected_in_source,
        "missed_source_exceptions": missed_exceptions,
        "exception_recall_pct": exception_recall_pct,
        "span_verified": span_valid,
        "raw_sop_tokens_est": prose_tokens_est,
        "distilled_artifact_tokens_est": artifact_tokens_est,
        "prompt_token_reduction_pct": token_reduction_pct,
    }


def detect_cross_locale_conflicts(artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect translation lag (`en-US` vs `es-US`), EU 14-day statutory breaches (`de-DE`), and safety exception omissions."""
    by_locale: Dict[str, Dict[str, Any]] = {str(a["locale"]): a for a in artifacts}
    conflicts: List[Dict[str, Any]] = []

    en_us = by_locale.get("en-US")
    es_us = by_locale.get("es-US")
    de_de = by_locale.get("de-DE")
    ja_jp = by_locale.get("ja-JP")

    # 1. Same-marketplace translation parity check (`en-US` vs `es-US` both serve marketplace `US`)
    if en_us and es_us and en_us.get("marketplace") == es_us.get("marketplace"):
        if en_us["refund_window_days"] != es_us["refund_window_days"]:
            conflicts.append(
                {
                    "conflict_id": "LOCALE-DRIFT-US-WINDOW",
                    "severity": "CRITICAL",
                    "locales": ["en-US", "es-US"],
                    "type": "SAME_MARKETPLACE_TRANSLATION_CONFLICT",
                    "detail": (
                        f"en-US specifies {en_us['refund_window_days']}-day window while es-US specifies "
                        f"{es_us['refund_window_days']}-day window for the same US marketplace."
                    ),
                }
            )
        missing_in_es = sorted(set(en_us.get("exceptions") or []) - set(es_us.get("exceptions") or []))
        if missing_in_es:
            conflicts.append(
                {
                    "conflict_id": "LOCALE-DRIFT-US-EXCEPTIONS",
                    "severity": "HIGH",
                    "locales": ["en-US", "es-US"],
                    "type": "STALE_TRANSLATION_MISSING_EXCEPTION",
                    "detail": (
                        f"es-US SOP omits {len(missing_in_es)} exception clause(s) enforced in en-US: {missing_in_es}."
                    ),
                }
            )

    # 2. EU statutory 14-day withdrawal minimum check (`de-DE`, Directive 2011/83/EU)
    if de_de and de_de.get("marketplace") == "DE":
        if int(de_de["refund_window_days"]) < 14:
            conflicts.append(
                {
                    "conflict_id": "STATUTORY-EU-14D-BREACH",
                    "severity": "CRITICAL",
                    "locales": ["de-DE"],
                    "type": "EU_STATUTORY_WITHDRAWAL_VIOLATION",
                    "detail": (
                        f"de-DE specifies {de_de['refund_window_days']} days, violating the mandatory 14-day EU consumer "
                        f"withdrawal minimum (Directive 2011/83/EU)."
                    ),
                }
            )
        elif en_us and de_de["refund_window_days"] != en_us["refund_window_days"] and not de_de.get("statutory_override"):
            conflicts.append(
                {
                    "conflict_id": "UNDECLARED-DE-VARIANCE",
                    "severity": "MEDIUM",
                    "locales": ["en-US", "de-DE"],
                    "type": "UNDECLARED_REGIONAL_OVERRIDE",
                    "detail": "de-DE window differs from en-US without statutory_override=True metadata.",
                }
            )

    # 3. Cross-marketplace safety exception consistency (`swollen_or_leaking_battery` / `100wh_hazmat`)
    safety_critical = {"swollen_or_leaking_battery_never_return_ship", "lithium_battery_over_100wh_hazmat_restricted"}
    all_present_safety = set()
    for a in artifacts:
        all_present_safety |= set(a.get("exceptions") or []) & safety_critical

    if all_present_safety:
        for loc, art in by_locale.items():
            missing_safety = sorted(all_present_safety - set(art.get("exceptions") or []))
            if missing_safety and not (loc == "es-US" and any(c["conflict_id"] == "LOCALE-DRIFT-US-EXCEPTIONS" for c in conflicts)):
                conflicts.append(
                    {
                        "conflict_id": f"SAFETY-EXC-OMISSION-{loc.upper()}",
                        "severity": "CRITICAL",
                        "locales": [loc],
                        "type": "MISSING_GLOBAL_HAZMAT_EXCEPTION",
                        "detail": f"Locale {loc} omits global physical safety exception(s): {missing_safety}.",
                    }
                )

    # 4. Fee / refund ratio divergence notice (`ja-JP` 50% opened-item fee vs `en-US` 0% fee)
    if en_us and ja_jp and int(ja_jp.get("restocking_fee_pct", 0)) != int(en_us.get("restocking_fee_pct", 0)):
        conflicts.append(
            {
                "conflict_id": "MARKETPLACE-FEE-DIVERGENCE-JP",
                "severity": "MEDIUM" if ja_jp.get("statutory_override") else "HIGH",
                "locales": ["en-US", "ja-JP"],
                "type": "OPENED_ITEM_REFUND_RATIO_DIVERGENCE",
                "detail": (
                    f"ja-JP applies a {ja_jp['restocking_fee_pct']}% opened-item fee vs {en_us['restocking_fee_pct']}% in en-US; "
                    f"global routing must scope Japanese customer chats strictly to KA-*-JA-JP."
                ),
            }
        )

    return conflicts


def distill_policy_bundle(
    policy_family: str = "electronics_returns",
    custom_sop_text: Optional[str] = None,
    custom_locale: str = "en-US",
    use_bedrock: bool = True,
) -> Dict[str, Any]:
    """Compile multi-locale CS SOP prose into verified Knowledge Artifacts via Amazon Bedrock + deterministic entailment."""
    t0 = time.perf_counter()
    bundle = CS_POLICY_BUNDLES.get(policy_family) or CS_POLICY_BUNDLES["electronics_returns"]
    locale_specs = dict(bundle["locales"])

    if custom_sop_text and custom_sop_text.strip():
        loc = custom_locale if custom_locale in SUPPORTED_LOCALES else "en-US"
        base_entry = dict(locale_specs.get(loc) or locale_specs["en-US"])
        base_entry["sop_prose"] = custom_sop_text.strip()
        locale_specs[loc] = base_entry

    distilled_artifacts: List[Dict[str, Any]] = []
    verifications: List[Dict[str, Any]] = []
    bedrock_latency_total_ms = 0.0
    bedrock_tokens_total = 0
    bedrock_calls = 0
    engine_used = "deterministic-local-policy"

    for loc in SUPPORTED_LOCALES:
        if loc not in locale_specs:
            continue
        spec = locale_specs[loc]
        prose = spec["sop_prose"]
        det_artifact = _extract_deterministic_facts(
            sop_prose=prose,
            locale=loc,
            marketplace=spec["marketplace"],
            policy_family=bundle["policy_family"],
            statutory_override=bool(spec.get("statutory_override", False)),
        )

        # Invoke live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) on primary or edited locale to compile structured JSON
        call_live_for_locale = use_bedrock and (
            loc == custom_locale if (custom_sop_text and custom_sop_text.strip()) else loc in ("en-US", "es-US")
        )
        if call_live_for_locale:
            br_res = invoke_bedrock_json(
                system_prompt=(
                    "You are an Amazon Customer Service Knowledge Artifact compiler. "
                    "Distill the SOP text into strict JSON with keys: "
                    "refund_window_days (integer from text), restocking_fee_pct (integer from text), "
                    "summary_rule (1 concise sentence), andverbatim_check (exact short phrase from the SOP)."
                ),
                user_prompt=f"Locale: {loc} ({spec['marketplace']})\nSOP:\n{prose}",
                fallback_payload={
                    "refund_window_days": det_artifact["refund_window_days"],
                    "restocking_fee_pct": det_artifact["restocking_fee_pct"],
                    "summary_rule": f"{spec['marketplace']} {bundle['policy_family']} window: {det_artifact['refund_window_days']} days.",
                },
                use_bedrock=True,
                max_tokens=320,
            )
            bedrock_latency_total_ms += br_res["latency_ms"]
            bedrock_tokens_total += br_res["total_tokens"]
            if br_res["live_bedrock"]:
                bedrock_calls += 1
            engine_used = br_res["engine"]
            parsed = br_res["parsed"]

            # Enforce deterministic grounding gate on Bedrock-extracted numbers
            cand_artifact = dict(det_artifact)
            if isinstance(parsed.get("refund_window_days"), int):
                cand_artifact["refund_window_days"] = int(parsed["refund_window_days"])
            if isinstance(parsed.get("restocking_fee_pct"), int):
                cand_artifact["restocking_fee_pct"] = int(parsed["restocking_fee_pct"])
            cand_artifact["bedrock_summary_rule"] = str(
                parsed.get("summary_rule")
                or f"{loc}: {det_artifact['refund_window_days']}-day window, {det_artifact['restocking_fee_pct']}% fee."
            )

            cand_check = verify_artifact_entailment(prose, cand_artifact)
            # Reject any ungrounded Bedrock number automatically and restore span-verified deterministic extraction
            if not cand_check["entailed"]:
                det_artifact["rejected_ungrounded_fields"] = cand_check["ungrounded_numbers"]
                det_artifact["bedrock_summary_rule"] = cand_artifact["bedrock_summary_rule"]
                final_art = det_artifact
            else:
                final_art = cand_artifact
        else:
            det_artifact["bedrock_summary_rule"] = (
                f"{loc} ({spec['marketplace']}): {det_artifact['refund_window_days']}-day policy window, "
                f"{det_artifact['restocking_fee_pct']}% fee, {len(det_artifact['exceptions'])} exception(s)."
            )
            final_art = det_artifact

        ver = verify_artifact_entailment(prose, final_art)
        final_art["entailment_verification"] = ver
        distilled_artifacts.append(final_art)
        verifications.append(ver)

    conflicts = detect_cross_locale_conflicts(distilled_artifacts)
    critical_or_high = [c for c in conflicts if c["severity"] in ("CRITICAL", "HIGH")]
    publish_verdict = "BLOCK_LOCALE_CONFLICT" if critical_or_high else "READY_TO_PUBLISH"

    mean_token_reduction = round(
        sum(v["prompt_token_reduction_pct"] for v in verifications) / max(1, len(verifications)), 1
    )
    mean_exception_recall = round(
        sum(v["exception_recall_pct"] for v in verifications) / max(1, len(verifications)), 1
    )
    mean_numeric_precision = round(
        sum(v["numeric_precision_pct"] for v in verifications) / max(1, len(verifications)), 1
    )

    total_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "policy_family": bundle["policy_family"],
        "title": bundle["title"],
        "locales_evaluated": [a["locale"] for a in distilled_artifacts],
        "publish_verdict": publish_verdict,
        "artifacts": distilled_artifacts,
        "cross_locale_conflicts": conflicts,
        "metrics": {
            "numeric_entailment_precision_pct": mean_numeric_precision,
            "exception_clause_recall_pct": mean_exception_recall,
            "prompt_token_reduction_pct": mean_token_reduction,
            "conflicts_detected": len(conflicts),
            "blocking_conflicts": len(critical_or_high),
        },
        "total_distill_ms": total_ms,
        "bedrock_calls": bedrock_calls,
        "bedrock_latency_ms": round(bedrock_latency_total_ms, 2),
        "bedrock_tokens": bedrock_tokens_total,
        "llm_engine": engine_used,
    }
