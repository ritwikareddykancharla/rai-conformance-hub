"""AST & CloudFormation/CDK Shadow-AI Discovery Scanner and Central SQLite WAL AI-BOM Registry."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .bedrock_client import invoke_bedrock_json

EXTERNAL_AI_DOMAINS = (
    "api.openai.com",
    "api.anthropic.com",
    "api.deepseek.com",
    "api.cohere.ai",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
)

EXTERNAL_AI_IMPORTS = {
    "openai": "openai-python-sdk",
    "anthropic": "anthropic-python-sdk",
    "cohere": "cohere-python-sdk",
    "mistralai": "mistral-python-sdk",
}

APPROVED_CATALOG_SEED: List[Dict[str, Any]] = [
    {
        "service_id": "cs-refund-assistant",
        "owner_team": "cs-ai-platform",
        "approved_models": ["us.amazon.nova-lite-v1:0", "us.amazon.nova-pro-v1:0"],
        "approved_regions": ["us-west-2", "us-east-1"],
        "guardrail_required": True,
        "max_retention_days": 30,
        "risk_tier": "TRANSPARENCY_LIMITED",
    },
    {
        "service_id": "catalog-tagger-v2",
        "owner_team": "retail-catalog-ml",
        "approved_models": ["us.amazon.nova-lite-v1:0", "sagemaker:catalog-taxonomy-v2"],
        "approved_regions": ["us-west-2"],
        "guardrail_required": True,
        "max_retention_days": 14,
        "risk_tier": "MINIMAL_RISK",
    },
    {
        "service_id": "seller-doc-ocr",
        "owner_team": "seller-trust-ops",
        "approved_models": ["sagemaker:seller-kyc-ocr-v3", "us.amazon.nova-lite-v1:0"],
        "approved_regions": ["us-west-2", "eu-west-1"],
        "guardrail_required": True,
        "max_retention_days": 30,
        "risk_tier": "HIGH_RISK",
    },
    {
        "service_id": "fulfillment-demand-forecaster",
        "owner_team": "sc-forecasting",
        "approved_models": ["sagemaker:fc-demand-tft-v4"],
        "approved_regions": ["us-west-2", "us-east-1"],
        "guardrail_required": False,
        "max_retention_days": 90,
        "risk_tier": "MINIMAL_RISK",
    },
    {
        "service_id": "prime-support-summarizer",
        "owner_team": "cx-summarization",
        "approved_models": ["us.amazon.nova-lite-v1:0"],
        "approved_regions": ["us-west-2"],
        "guardrail_required": True,
        "max_retention_days": 30,
        "risk_tier": "TRANSPARENCY_LIMITED",
    },
    {
        "service_id": "seller-lending-underwriter",
        "owner_team": "merchant-credit-ml",
        "approved_models": ["sagemaker:merchant-credit-xgb-v5"],
        "approved_regions": ["us-west-2"],
        "guardrail_required": False,
        "max_retention_days": 30,
        "risk_tier": "HIGH_RISK",
    },
]


# 12 synthetic microservice repositories covering registered compliant, shadow AI, and drifted services.
SYNTHETIC_FLEET_REPOS: List[Dict[str, Any]] = [
    {
        "repo_id": "repo-01-cs-refund-assistant",
        "service_id": "cs-refund-assistant",
        "title": "Customer Service Refund Assistant (Compliant Registered)",
        "deploy_region": "us-west-2",
        "expected_status": "COMPLIANT_REGISTERED",
        "python_code": '''import boto3

SYSTEM_PROMPT = "You are an Amazon CS refund assistant. Cite verified policy artifacts and never invent exception windows."
TOOLS = [{"toolSpec": {"name": "lookup_order_status"}}, {"toolSpec": {"name": "fetch_policy_artifact"}}]

def answer_customer(query: str, s3_client, bedrock_client):
    resp = bedrock_client.converse(
        modelId="us.amazon.nova-lite-v1:0",
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": query}]}],
        guardrailConfig={"guardrailIdentifier": "gr-cs-pii-filter-01", "guardrailVersion": "2"},
        toolConfig={"tools": TOOLS},
    )
    s3_client.put_object(Bucket="cs-redacted-audit-30d", Key="traces/redacted.json", Body=b"{}")
    return resp
''',
        "iac_template": {
            "Resources": {
                "CSBedrockGuardrail": {
                    "Type": "AWS::Bedrock::Guardrail",
                    "Properties": {"Name": "gr-cs-pii-filter-01", "BlockedInputMessaging": "PII blocked"},
                },
                "TraceArchiveBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "cs-redacted-audit-30d",
                        "LifecycleConfiguration": {"Rules": [{"Status": "Enabled", "ExpirationInDays": 30}]},
                    },
                },
                "InvokeRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "Policies": [
                            {
                                "PolicyName": "ScopedBedrock",
                                "PolicyDocument": {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["bedrock:InvokeModel"],
                                            "Resource": "arn:aws:bedrock:us-west-2:796330847946:inference-profile/us.amazon.nova-lite-v1:0",
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                },
            }
        },
    },
    {
        "repo_id": "repo-02-shadow-hr-screener",
        "service_id": "hr-fasttrack-resume-bot",
        "title": "Unregistered HR Resume Ranker Calling External OpenAI API",
        "deploy_region": "us-east-1",
        "expected_status": "SHADOW_UNREGISTERED",
        "python_code": '''import openai
import boto3

SYSTEM_PROMPT = "Score job applicants from 1 to 100 and auto-reject candidates below 65 without recruiter review."
TOOLS = [{"name": "auto_reject_applicant_ats"}, {"name": "write_candidate_dossier"}]

def screen_resume(raw_resume_text: str):
    client = openai.OpenAI()
    out = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": raw_resume_text}],
    )
    s3 = boto3.client("s3")
    s3.put_object(Bucket="hr-raw-resumes-archive", Key="unredacted/candidate.txt", Body=raw_resume_text.encode())
    return out
''',
        "iac_template": {
            "Resources": {
                "RawResumeBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": "hr-raw-resumes-archive"},
                }
            }
        },
    },
    {
        "repo_id": "repo-03-catalog-tagger-v2",
        "service_id": "catalog-tagger-v2",
        "title": "Retail Catalog Taxonomy Tagger (Compliant Registered)",
        "deploy_region": "us-west-2",
        "expected_status": "COMPLIANT_REGISTERED",
        "python_code": '''import boto3

SYSTEM_PROMPT = "Assign browse-node taxonomy IDs to product titles using approved catalog attributes."

def tag_item(title: str):
    br = boto3.client("bedrock-runtime", region_name="us-west-2")
    resp = br.converse(
        modelId="us.amazon.nova-lite-v1:0",
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": title}]}],
        guardrailConfig={"guardrailIdentifier": "gr-catalog-safety-02", "guardrailVersion": "1"},
    )
    return resp
''',
        "iac_template": {
            "Resources": {
                "CatalogGuardrail": {
                    "Type": "AWS::Bedrock::Guardrail",
                    "Properties": {"Name": "gr-catalog-safety-02"},
                },
                "CatalogLogsBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "catalog-tag-logs-14d",
                        "LifecycleConfiguration": {"Rules": [{"Status": "Enabled", "ExpirationInDays": 14}]},
                    },
                },
            }
        },
    },
    {
        "repo_id": "repo-04-shadow-marketing-copy-agent",
        "service_id": "growth-promo-writer-exp",
        "title": "Shadow Marketing Agent Using Unregistered Bedrock + Wildcard IAM",
        "deploy_region": "us-west-2",
        "expected_status": "SHADOW_UNREGISTERED",
        "python_code": '''import boto3

SYSTEM_PROMPT = "Generate urgent promotional claims and dispatch campaign emails directly to customer cohorts."
TOOLS = [{"toolSpec": {"name": "blast_ses_campaign"}}]

def generate_campaign(segment_notes: str):
    br = boto3.client("bedrock-runtime")
    return br.converse(
        modelId="anthropic.claude-3-5-sonnet-20241022-v2:0",
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": segment_notes}]}],
        toolConfig={"tools": TOOLS},
    )
''',
        "iac_template": {
            "Resources": {
                "WildcardBedrockRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "Policies": [
                            {
                                "PolicyName": "AllowAllModels",
                                "PolicyDocument": {
                                    "Statement": [{"Effect": "Allow", "Action": ["bedrock:*"], "Resource": "*"}]
                                },
                            }
                        ]
                    },
                }
            }
        },
    },
    {
        "repo_id": "repo-05-drifted-prime-eu-summarizer",
        "service_id": "prime-support-summarizer",
        "title": "Registered Support Summarizer Drifted to eu-central-1 Without Guardrail",
        "deploy_region": "eu-central-1",
        "expected_status": "DRIFT_VIOLATION",
        "python_code": '''import boto3

SYSTEM_PROMPT = "Summarize German and French Prime customer chat transcripts including billing notes."

def summarize_chat(transcript: str):
    br = boto3.client("bedrock-runtime", region_name="eu-central-1")
    resp = br.converse(
        modelId="us.amazon.nova-lite-v1:0",
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": transcript}]}],
    )
    firehose = boto3.client("firehose")
    firehose.put_record(DeliveryStreamName="raw-eu-chat-archive", Record={"Data": transcript.encode()})
    return resp
''',
        "iac_template": {
            "Resources": {
                "TranscriptBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "raw-eu-chat-archive-bucket",
                        "LifecycleConfiguration": {"Rules": [{"Status": "Enabled", "ExpirationInDays": 365}]},
                    },
                }
            }
        },
    },
    {
        "repo_id": "repo-06-seller-doc-ocr",
        "service_id": "seller-doc-ocr",
        "title": "Seller Identity Verification OCR Pipeline (Compliant Registered)",
        "deploy_region": "us-west-2",
        "expected_status": "COMPLIANT_REGISTERED",
        "python_code": '''import boto3

SYSTEM_PROMPT = "Extract business registration fields and route low-confidence documents to human compliance specialists."

def verify_seller_doc(payload_bytes: bytes):
    sm = boto3.client("sagemaker-runtime", region_name="us-west-2")
    ocr_out = sm.invoke_endpoint(EndpointName="seller-kyc-ocr-v3", Body=payload_bytes)
    br = boto3.client("bedrock-runtime", region_name="us-west-2")
    return br.converse(
        modelId="us.amazon.nova-lite-v1:0",
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": str(ocr_out)}]}],
        guardrailConfig={"guardrailIdentifier": "gr-seller-pii-03", "guardrailVersion": "1"},
    )
''',
        "iac_template": {
            "Resources": {
                "SellerKycEndpoint": {
                    "Type": "AWS::SageMaker::Endpoint",
                    "Properties": {"EndpointName": "seller-kyc-ocr-v3"},
                },
                "SellerGuardrail": {
                    "Type": "AWS::Bedrock::Guardrail",
                    "Properties": {"Name": "gr-seller-pii-03"},
                },
                "AuditBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "seller-kyc-redacted-30d",
                        "LifecycleConfiguration": {"Rules": [{"Status": "Enabled", "ExpirationInDays": 30}]},
                    },
                },
            }
        },
    },
    {
        "repo_id": "repo-07-shadow-deepseek-code-helper",
        "service_id": "internal-sql-debugger-bot",
        "title": "Shadow SQL Helper Posting Production Schemas to External HTTPS Endpoint",
        "deploy_region": "us-west-2",
        "expected_status": "SHADOW_UNREGISTERED",
        "python_code": '''import json
import urllib.request

SYSTEM_PROMPT = "Rewrite slow warehouse SQL queries using full table schemas and sample customer rows."

def optimize_sql(schema_ddl: str):
    req = urllib.request.Request(
        "https://api.deepseek.com/v1/chat/completions",
        data=json.dumps({"model": "deepseek-coder", "prompt": schema_ddl}).encode(),
    )
    return urllib.request.urlopen(req, timeout=10)
''',
        "iac_template": {"Resources": {}},
    },
    {
        "repo_id": "repo-08-fulfillment-demand-forecaster",
        "service_id": "fulfillment-demand-forecaster",
        "title": "Fulfillment Center Time-Series Forecaster (Compliant Registered)",
        "deploy_region": "us-west-2",
        "expected_status": "COMPLIANT_REGISTERED",
        "python_code": '''import boto3

def predict_fc_units(csv_features: bytes):
    sm = boto3.client("sagemaker-runtime", region_name="us-west-2")
    return sm.invoke_endpoint(EndpointName="fc-demand-tft-v4", ContentType="text/csv", Body=csv_features)
''',
        "iac_template": {
            "Resources": {
                "ForecastEndpoint": {
                    "Type": "AWS::SageMaker::Endpoint",
                    "Properties": {"EndpointName": "fc-demand-tft-v4"},
                },
                "FeatureSnapshotBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "fc-demand-snapshots-60d",
                        "LifecycleConfiguration": {"Rules": [{"Status": "Enabled", "ExpirationInDays": 60}]},
                    },
                },
            }
        },
    },
    {
        "repo_id": "repo-09-shadow-vendor-negotiation-bot",
        "service_id": "vendor-rebate-negotiator",
        "title": "Unregistered Vendor Contract Agent With Autonomous DynamoDB Write Tool",
        "deploy_region": "us-east-1",
        "expected_status": "SHADOW_UNREGISTERED",
        "python_code": '''import boto3

SYSTEM_PROMPT = "Negotiate supplier rebate terms and commit revised payment discounts directly to vendor_contracts."
TOOLS = [{"toolSpec": {"name": "commit_vendor_discount_terms"}}]

def negotiate_terms(email_body: str):
    br = boto3.client("bedrock-runtime", region_name="us-east-1")
    out = br.invoke_model(modelId="amazon.titan-text-express-v1", body=email_body.encode())
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="vendor_raw_negotiation_prompts", Item={"pk": {"S": "v1"}, "raw": {"S": email_body}})
    return out
''',
        "iac_template": {
            "Resources": {
                "VendorPromptTable": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {"TableName": "vendor_raw_negotiation_prompts"},
                }
            }
        },
    },
    {
        "repo_id": "repo-10-drifted-seller-underwriter-model",
        "service_id": "seller-lending-underwriter",
        "title": "Registered Seller Underwriter Swapped to Unapproved Endpoint + 730d Retention",
        "deploy_region": "us-west-2",
        "expected_status": "DRIFT_VIOLATION",
        "python_code": '''import boto3

def score_loan_application(features_json: bytes):
    sm = boto3.client("sagemaker-runtime", region_name="us-west-2")
    res = sm.invoke_endpoint(EndpointName="merchant-credit-experimental-unvetted-v9", Body=features_json)
    s3 = boto3.client("s3")
    s3.put_object(Bucket="merchant-credit-raw-features", Key="apps/raw.json", Body=features_json)
    return res
''',
        "iac_template": {
            "Resources": {
                "UnvettedEndpoint": {
                    "Type": "AWS::SageMaker::Endpoint",
                    "Properties": {"EndpointName": "merchant-credit-experimental-unvetted-v9"},
                },
                "RawFeaturesBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "merchant-credit-raw-features",
                        "LifecycleConfiguration": {"Rules": [{"Status": "Enabled", "ExpirationInDays": 730}]},
                    },
                },
            }
        },
    },
    {
        "repo_id": "repo-11-shadow-returns-fraud-freeze",
        "service_id": "buyer-abuse-auto-freeze",
        "title": "Unregistered Buyer Account Freeze Model Calling External Anthropic SDK",
        "deploy_region": "us-west-2",
        "expected_status": "SHADOW_UNREGISTERED",
        "python_code": '''import anthropic

SYSTEM_PROMPT = "Analyze buyer return claim notes and trigger immediate account suspension when fraud score > 0.7."
TOOLS = [{"name": "suspend_customer_account"}]

def evaluate_return_abuse(notes: str):
    client = anthropic.Anthropic()
    return client.messages.create(
        model="claude-3-5-haiku-latest",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": notes}],
    )
''',
        "iac_template": {"Resources": {}},
    },
    {
        "repo_id": "repo-12-drifted-cs-refund-unguarded",
        "service_id": "cs-refund-assistant",
        "title": "Registered CS Refund Assistant PR Removing Bedrock Guardrail & Swapping Model",
        "deploy_region": "us-west-2",
        "expected_status": "DRIFT_VIOLATION",
        "python_code": '''import boto3

SYSTEM_PROMPT = "Issue instant full refunds without checking return window policy artifacts."
TOOLS = [{"toolSpec": {"name": "issue_instant_refund"}}]

def answer_customer_fast(query: str):
    br = boto3.client("bedrock-runtime", region_name="us-west-2")
    return br.converse(
        modelId="meta.llama3-70b-instruct-v1:0",
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": query}]}],
        toolConfig={"tools": TOOLS},
    )
''',
        "iac_template": {
            "Resources": {
                "TraceArchiveBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": "cs-unbounded-debug-prompts"},
                }
            }
        },
    },
]


class _PythonAIBomVisitor(ast.NodeVisitor):
    """AST visitor extracting foundation-model calls, external APIs, prompts, tools, guardrails, and sinks."""

    def __init__(self) -> None:
        self.imports: List[str] = []
        self.external_sdks: List[str] = []
        self.model_invocations: List[Dict[str, Any]] = []
        self.external_urls: List[str] = []
        self.system_prompts: List[Dict[str, str]] = []
        self.tools: List[str] = []
        self.data_sinks: List[Dict[str, Any]] = []
        self.code_guardrail_ids: List[str] = []

    @staticmethod
    def _const_str(node: Optional[ast.AST]) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _collect_strings(self, node: ast.AST, out: List[str]) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(node.value)
        for child in ast.iter_child_nodes(node):
            self._collect_strings(child, out)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            root_mod = alias.name.split(".")[0]
            self.imports.append(alias.name)
            if root_mod in EXTERNAL_AI_IMPORTS:
                self.external_sdks.append(EXTERNAL_AI_IMPORTS[root_mod])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module:
            root_mod = node.module.split(".")[0]
            self.imports.append(node.module)
            if root_mod in EXTERNAL_AI_IMPORTS:
                self.external_sdks.append(EXTERNAL_AI_IMPORTS[root_mod])
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_upper = target.id.upper()
                if "PROMPT" in name_upper:
                    val = self._const_str(node.value)
                    if val:
                        digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:12]
                        self.system_prompts.append(
                            {"symbol": target.id, "sha256_12": digest, "preview": val[:140]}
                        )
                if "TOOL" in name_upper:
                    strs: List[str] = []
                    self._collect_strings(node.value, strs)
                    for idx, s in enumerate(strs):
                        if s in ("name",) and idx + 1 < len(strs):
                            self.tools.append(strs[idx + 1])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        kw_map: Dict[str, ast.AST] = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        # Check all string literals inside call arguments for external AI API URLs
        call_strings: List[str] = []
        self._collect_strings(node, call_strings)
        for s in call_strings:
            for dom in EXTERNAL_AI_DOMAINS:
                if dom in s and s not in self.external_urls:
                    self.external_urls.append(s)

        # Bedrock Converse / InvokeModel
        if func_name in ("converse", "converse_stream", "invoke_model", "invoke_model_with_response_stream"):
            model_id = self._const_str(kw_map.get("modelId")) or "unknown-bedrock-model"
            has_guardrail = "guardrailConfig" in kw_map or "guardrailIdentifier" in kw_map
            if "guardrailConfig" in kw_map:
                gr_strs: List[str] = []
                self._collect_strings(kw_map["guardrailConfig"], gr_strs)
                for idx, token in enumerate(gr_strs):
                    if token == "guardrailIdentifier" and idx + 1 < len(gr_strs):
                        self.code_guardrail_ids.append(gr_strs[idx + 1])
            self.model_invocations.append(
                {
                    "provider": "aws-bedrock-runtime",
                    "api": func_name,
                    "model_id": model_id,
                    "guardrail_attached_in_code": has_guardrail,
                    "line": getattr(node, "lineno", 1),
                }
            )

        # SageMaker Runtime InvokeEndpoint
        elif func_name == "invoke_endpoint":
            ep_name = self._const_str(kw_map.get("EndpointName")) or "unknown-sagemaker-endpoint"
            self.model_invocations.append(
                {
                    "provider": "aws-sagemaker-runtime",
                    "api": "invoke_endpoint",
                    "model_id": f"sagemaker:{ep_name}",
                    "guardrail_attached_in_code": False,
                    "line": getattr(node, "lineno", 1),
                }
            )

        # External OpenAI / Anthropic SDK completions
        elif func_name == "create" and "model" in kw_map:
            ext_model = self._const_str(kw_map.get("model")) or "external-llm"
            self.model_invocations.append(
                {
                    "provider": "unapproved-external-sdk",
                    "api": "create",
                    "model_id": ext_model,
                    "guardrail_attached_in_code": False,
                    "line": getattr(node, "lineno", 1),
                }
            )

        # Data retention sinks (S3, Firehose, DynamoDB)
        if func_name == "put_object":
            bucket = self._const_str(kw_map.get("Bucket")) or "unknown-s3-bucket"
            self.data_sinks.append({"sink_type": "s3:PutObject", "target": bucket, "line": getattr(node, "lineno", 1)})
        elif func_name == "put_record":
            stream = self._const_str(kw_map.get("DeliveryStreamName")) or "unknown-firehose"
            self.data_sinks.append(
                {"sink_type": "firehose:PutRecord", "target": stream, "line": getattr(node, "lineno", 1)}
            )
        elif func_name == "put_item":
            table = self._const_str(kw_map.get("TableName")) or "unknown-dynamodb-table"
            self.data_sinks.append(
                {"sink_type": "dynamodb:PutItem", "target": table, "line": getattr(node, "lineno", 1)}
            )

        self.generic_visit(node)


class AIBomRegistry:
    """SQLite WAL central AI-BOM registry + AST/IaC shadow-AI discovery engine."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        base_dir = Path(os.environ.get("RAI_RUNTIME_DIR", "/tmp/rai-conformance-runtime"))
        base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else (base_dir / "rai_conformance.db")
        self._lock = threading.Lock()
        self._init_and_seed()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_and_seed(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS approved_ai_bom (
                        service_id TEXT PRIMARY KEY,
                        owner_team TEXT NOT NULL,
                        approved_models_json TEXT NOT NULL,
                        approved_regions_json TEXT NOT NULL,
                        guardrail_required INTEGER NOT NULL,
                        max_retention_days INTEGER NOT NULL,
                        risk_tier TEXT NOT NULL
                    )
                    """
                )
                for item in APPROVED_CATALOG_SEED:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO approved_ai_bom
                        (service_id, owner_team, approved_models_json, approved_regions_json, guardrail_required, max_retention_days, risk_tier)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            item["service_id"],
                            item["owner_team"],
                            json.dumps(item["approved_models"]),
                            json.dumps(item["approved_regions"]),
                            1 if item["guardrail_required"] else 0,
                            int(item["max_retention_days"]),
                            item["risk_tier"],
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

    def list_approved_systems(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM approved_ai_bom ORDER BY service_id ASC").fetchall()
            finally:
                conn.close()
        return [
            {
                "service_id": r["service_id"],
                "owner_team": r["owner_team"],
                "approved_models": json.loads(r["approved_models_json"]),
                "approved_regions": json.loads(r["approved_regions_json"]),
                "guardrail_required": bool(r["guardrail_required"]),
                "max_retention_days": int(r["max_retention_days"]),
                "risk_tier": r["risk_tier"],
            }
            for r in rows
        ]

    def get_approved_entry(self, service_id: str) -> Optional[Dict[str, Any]]:
        for entry in self.list_approved_systems():
            if entry["service_id"] == service_id:
                return entry
        return None

    @staticmethod
    def _inspect_iac_template(iac_template: Dict[str, Any]) -> Dict[str, Any]:
        resources = (iac_template or {}).get("Resources") or {}
        iac_guardrails: List[str] = []
        sagemaker_endpoints: List[str] = []
        bucket_retentions: Dict[str, Optional[int]] = {}
        ddb_ttl_enabled: Dict[str, bool] = {}
        wildcard_iam_roles: List[str] = []

        for logical_id, spec in resources.items():
            if not isinstance(spec, dict):
                continue
            rtype = str(spec.get("Type") or "")
            props = spec.get("Properties") or {}

            if rtype == "AWS::Bedrock::Guardrail":
                iac_guardrails.append(str(props.get("Name") or logical_id))
            elif rtype == "AWS::SageMaker::Endpoint":
                sagemaker_endpoints.append(str(props.get("EndpointName") or logical_id))
            elif rtype == "AWS::S3::Bucket":
                bname = str(props.get("BucketName") or logical_id)
                rules = ((props.get("LifecycleConfiguration") or {}).get("Rules")) or []
                exp_days: Optional[int] = None
                for rule in rules:
                    if isinstance(rule, dict) and rule.get("Status") == "Enabled" and "ExpirationInDays" in rule:
                        exp_days = int(rule["ExpirationInDays"])
                bucket_retentions[bname] = exp_days
            elif rtype == "AWS::DynamoDB::Table":
                tname = str(props.get("TableName") or logical_id)
                ttl_spec = props.get("TimeToLiveSpecification") or {}
                ddb_ttl_enabled[tname] = bool(ttl_spec.get("Enabled"))
            elif rtype == "AWS::IAM::Role":
                for pol in props.get("Policies") or []:
                    stmts = ((pol.get("PolicyDocument") or {}).get("Statement")) or []
                    for st in stmts:
                        actions = st.get("Action") or []
                        if isinstance(actions, str):
                            actions = [actions]
                        res = st.get("Resource")
                        if res == "*" and any("bedrock" in a or a == "*" for a in actions):
                            wildcard_iam_roles.append(logical_id)

        return {
            "iac_guardrails": iac_guardrails,
            "sagemaker_endpoints": sagemaker_endpoints,
            "bucket_retentions": bucket_retentions,
            "ddb_ttl_enabled": ddb_ttl_enabled,
            "wildcard_iam_roles": wildcard_iam_roles,
        }

    def scan_workload(
        self,
        service_id: str,
        python_code: str,
        iac_template: Optional[Dict[str, Any]] = None,
        deploy_region: str = "us-west-2",
        repo_id: str = "custom-repo",
        use_bedrock: bool = False,
    ) -> Dict[str, Any]:
        """Parse Python AST + CloudFormation/CDK template and reconcile against the SQLite AI-BOM Registry."""
        t0 = time.perf_counter()
        tree = ast.parse(python_code or "")
        visitor = _PythonAIBomVisitor()
        visitor.visit(tree)

        iac_info = self._inspect_iac_template(iac_template or {})
        reg_entry = self.get_approved_entry(service_id)

        findings: List[Dict[str, str]] = []
        discovered_models = [m["model_id"] for m in visitor.model_invocations]
        for url in visitor.external_urls:
            discovered_models.append(f"external-http:{url}")

        # 1. Check central AI-BOM registration
        if reg_entry is None:
            findings.append(
                {
                    "code": "BOM-SHADOW-001",
                    "severity": "CRITICAL",
                    "detail": f"Service '{service_id}' invokes AI models ({', '.join(discovered_models) or 'unlisted'}) with zero registration in the central SQLite AI-BOM catalog.",
                }
            )

        # 2. Check unapproved external APIs / SDKs
        if visitor.external_sdks or visitor.external_urls:
            ext_desc = ", ".join(sorted(set(visitor.external_sdks + visitor.external_urls)))
            findings.append(
                {
                    "code": "BOM-EXT-API-002",
                    "severity": "CRITICAL",
                    "detail": f"Detected outbound third-party AI SDK or endpoint outside VPC governance ({ext_desc}).",
                }
            )

        # 3. Reconcile against registered AI-BOM policy if registered
        if reg_entry is not None:
            if deploy_region not in reg_entry["approved_regions"]:
                findings.append(
                    {
                        "code": "BOM-REGION-DRIFT-003",
                        "severity": "HIGH",
                        "detail": f"Deployment region '{deploy_region}' is outside approved AI-BOM regions {reg_entry['approved_regions']}.",
                    }
                )
            for inv in visitor.model_invocations:
                if inv["model_id"] not in reg_entry["approved_models"]:
                    findings.append(
                        {
                            "code": "BOM-MODEL-DRIFT-004",
                            "severity": "HIGH",
                            "detail": f"Model '{inv['model_id']}' is not in approved AI-BOM model list {reg_entry['approved_models']}.",
                        }
                    )
            if reg_entry["guardrail_required"]:
                any_bedrock = [m for m in visitor.model_invocations if m["provider"] == "aws-bedrock-runtime"]
                if any_bedrock and (not all(m["guardrail_attached_in_code"] for m in any_bedrock) or not iac_info["iac_guardrails"]):
                    findings.append(
                        {
                            "code": "BOM-GUARDRAIL-005",
                            "severity": "HIGH",
                            "detail": "Registered workload requires AWS::Bedrock::Guardrail in IaC and guardrailConfig on every Converse/InvokeModel call.",
                        }
                    )
        else:
            # Even on unregistered services, flag missing guardrails on LLM calls
            if visitor.model_invocations and not iac_info["iac_guardrails"]:
                findings.append(
                    {
                        "code": "BOM-GUARDRAIL-005",
                        "severity": "HIGH",
                        "detail": "Foundation-model invocation has no AWS::Bedrock::Guardrail resource or runtime guardrailConfig.",
                    }
                )

        # 4. Check IaC wildcard IAM and data-retention sinks
        if iac_info["wildcard_iam_roles"]:
            findings.append(
                {
                    "code": "BOM-IAM-WILDCARD-006",
                    "severity": "HIGH",
                    "detail": f"IAM role(s) {iac_info['wildcard_iam_roles']} grant wildcard bedrock:* on Resource '*'.",
                }
            )

        max_allowed_days = int(reg_entry["max_retention_days"]) if reg_entry else 30
        for sink in visitor.data_sinks:
            target = sink["target"]
            if sink["sink_type"] == "s3:PutObject":
                exp = iac_info["bucket_retentions"].get(target)
                if exp is None:
                    findings.append(
                        {
                            "code": "BOM-RETENTION-007",
                            "severity": "MEDIUM",
                            "detail": f"Prompt/trace S3 sink '{target}' lacks LifecycleConfiguration ExpirationInDays.",
                        }
                    )
                elif exp > max_allowed_days:
                    findings.append(
                        {
                            "code": "BOM-RETENTION-007",
                            "severity": "MEDIUM",
                            "detail": f"S3 sink '{target}' retains data for {exp} days, exceeding policy cap of {max_allowed_days} days.",
                        }
                    )
            elif sink["sink_type"] == "firehose:PutRecord":
                # Check if any bucket in IaC exceeds max_allowed_days
                for bname, exp in iac_info["bucket_retentions"].items():
                    if exp is None or exp > max_allowed_days:
                        findings.append(
                            {
                                "code": "BOM-RETENTION-007",
                                "severity": "MEDIUM",
                                "detail": f"Firehose archive bucket '{bname}' retention ({exp} days) exceeds {max_allowed_days}-day limit.",
                            }
                        )
            elif sink["sink_type"] == "dynamodb:PutItem":
                if not iac_info["ddb_ttl_enabled"].get(target, False):
                    findings.append(
                        {
                            "code": "BOM-RETENTION-007",
                            "severity": "MEDIUM",
                            "detail": f"DynamoDB prompt table '{target}' has no TimeToLiveSpecification enabled.",
                        }
                    )

        if reg_entry is None:
            status = "SHADOW_UNREGISTERED"
        elif findings:
            status = "DRIFT_VIOLATION"
        else:
            status = "COMPLIANT_REGISTERED"

        scan_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        remediation_fallback = {
            "executive_summary": (
                f"Service '{service_id}' in {deploy_region} evaluated as {status} with {len(findings)} governance finding(s)."
            ),
            "priority_actions": [f["detail"] for f in findings[:3]]
            or ["All AST invocations, Bedrock Guardrails, and S3 retention rules match the registered AI-BOM."],
        }
        bedrock_meta = invoke_bedrock_json(
            system_prompt=(
                "You are an Amazon Responsible AI Principal Engineer. Return concise JSON with keys "
                "'executive_summary' (string) and 'priority_actions' (list of up to 3 concrete engineering fixes)."
            ),
            user_prompt=json.dumps(
                {
                    "service_id": service_id,
                    "deploy_region": deploy_region,
                    "status": status,
                    "discovered_models": discovered_models,
                    "tools": visitor.tools,
                    "findings": findings,
                }
            ),
            fallback_payload=remediation_fallback,
            use_bedrock=use_bedrock,
        )

        return {
            "repo_id": repo_id,
            "service_id": service_id,
            "deploy_region": deploy_region,
            "conformance_status": status,
            "registered_in_bom": reg_entry is not None,
            "scan_ms": scan_ms,
            "ai_bom_entry": {
                "models": visitor.model_invocations,
                "external_sdks": sorted(set(visitor.external_sdks)),
                "external_urls": visitor.external_urls,
                "system_prompts": visitor.system_prompts,
                "agent_tools": sorted(set(visitor.tools)),
                "data_retention_sinks": visitor.data_sinks,
                "code_guardrail_ids": sorted(set(visitor.code_guardrail_ids)),
                "iac_guardrails": iac_info["iac_guardrails"],
                "iac_bucket_retentions": iac_info["bucket_retentions"],
                "iac_wildcard_iam_roles": iac_info["wildcard_iam_roles"],
            },
            "findings": findings,
            "remediation_brief": bedrock_meta["parsed"],
            "bedrock_latency_ms": bedrock_meta["latency_ms"],
            "bedrock_tokens": bedrock_meta["total_tokens"],
            "live_bedrock": bedrock_meta["live_bedrock"],
            "llm_engine": bedrock_meta["engine"],
        }

    def scan_synthetic_fleet(self, use_bedrock_on_flagged: bool = False) -> Dict[str, Any]:
        t0 = time.perf_counter()
        results: List[Dict[str, Any]] = []
        for idx, repo in enumerate(SYNTHETIC_FLEET_REPOS):
            call_bedrock = use_bedrock_on_flagged and idx == 1
            res = self.scan_workload(
                service_id=repo["service_id"],
                python_code=repo["python_code"],
                iac_template=repo["iac_template"],
                deploy_region=repo["deploy_region"],
                repo_id=repo["repo_id"],
                use_bedrock=call_bedrock,
            )
            res["title"] = repo["title"]
            res["expected_status"] = repo["expected_status"]
            res["matched_expected"] = res["conformance_status"] == repo["expected_status"]
            results.append(res)

        total_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        shadow_count = sum(1 for r in results if r["conformance_status"] == "SHADOW_UNREGISTERED")
        drift_count = sum(1 for r in results if r["conformance_status"] == "DRIFT_VIOLATION")
        compliant_count = sum(1 for r in results if r["conformance_status"] == "COMPLIANT_REGISTERED")
        exact_matches = sum(1 for r in results if r["matched_expected"])

        return {
            "repos_scanned": len(results),
            "compliant_registered": compliant_count,
            "shadow_unregistered": shadow_count,
            "drift_violations": drift_count,
            "classification_matches": exact_matches,
            "discovery_accuracy_pct": round((exact_matches / max(1, len(results))) * 100.0, 1),
            "total_scan_ms": total_ms,
            "results": results,
        }
