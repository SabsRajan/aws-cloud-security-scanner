"""
AWS Security Scanner
--------------------
Agentless multi-service AWS security posture scanner with optional
interactive remediation and AI-powered executive summary via Google Gemini.

Usage:
    python aws_security_scanner.py [--profile PROFILE] [--regions us-east-1,eu-west-1]
                                   [--remediate] [--output-dir ./reports]
                                   [--secret-name my/secret] [--key-age-days 90]
"""

import argparse
import concurrent.futures
import datetime
import html
import json
import logging
import os
import sys
from typing import Optional

import boto3
import botocore.exceptions
import google.generativeai as genai

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants (overridable via CLI)
# ---------------------------------------------------------------------------
DEFAULT_RISKY_PORTS: list[int] = [22, 3389, 3306, 5432, 1433, 27017, 6379]
DEFAULT_KEY_AGE_DAYS: int = 90
DEFAULT_SECRET_NAME: str = "grok-scanner/api-keys"
DEFAULT_OUTPUT_DIR: str = "."
GEMINI_MODEL: str = "gemini-2.5-flash"
MAX_SCAN_WORKERS: int = 10  # ThreadPoolExecutor ceiling for region parallelism


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class AWSSecurityScanner:
    """
    Scans an AWS account for common security misconfigurations across S3,
    EC2, IAM, Lambda, RDS, EBS, KMS, and CloudTrail.
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        regions: Optional[list[str]] = None,
        remediate: bool = False,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        secret_name: str = DEFAULT_SECRET_NAME,
        risky_ports: Optional[list[int]] = None,
        key_age_days: int = DEFAULT_KEY_AGE_DAYS,
    ) -> None:
        self.session = boto3.Session(profile_name=profile)
        self.remediate = remediate
        self.output_dir = output_dir
        self.secret_name = secret_name
        self.risky_ports = risky_ports or DEFAULT_RISKY_PORTS
        self.key_age_days = key_age_days
        self.findings: list[dict] = []
        self._gemini_api_key: Optional[str] = None  # cached after first fetch

        # Resolve regions once at startup
        if regions:
            self.regions = regions
        else:
            ec2_client = self.session.client("ec2")
            try:
                self.regions = [
                    r["RegionName"]
                    for r in ec2_client.describe_regions()["Regions"]
                ]
            except botocore.exceptions.ClientError as exc:
                logger.error("Could not list AWS regions: %s", exc)
                sys.exit(1)

        os.makedirs(self.output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(
        self,
        severity: str,
        title: str,
        resource: str,
        details: str = "",
        region: str = "global",
        remediation: str = "",
        remediator=None,  # optional callable(finding) invoked during remediation phase
    ) -> None:
        """Record a finding and emit a log line."""
        risk_score = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 1)
        self.findings.append(
            {
                "severity": severity,
                "title": title,
                "resource": resource,
                "region": region,
                "details": details,
                "remediation": remediation,
                "score": risk_score,
                "remediator": remediator,
            }
        )
        emoji = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(severity, "⚪")
        logger.info("%s [%s] %s → %s (%s)", emoji, severity, title, resource, region)

    def _paginate(self, client, operation: str, result_key: str, **kwargs) -> list:
        """Generic paginator helper — returns a flat list of all items."""
        items: list = []
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(result_key, []))
        except botocore.exceptions.OperationNotPageableError:
            # Fall back for operations that don't support pagination
            response = getattr(client, operation.replace("-", "_"))(**kwargs)
            items = response.get(result_key, [])
        return items

    # ------------------------------------------------------------------
    # Scan functions
    # ------------------------------------------------------------------

    def scan_s3(self) -> None:
        """Check S3 buckets for public access block gaps and public ACLs."""
        logger.info("🔍 Scanning S3 buckets...")
        s3 = self.session.client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except botocore.exceptions.ClientError as exc:
            logger.error("S3 scan error: %s", exc)
            return

        for bucket in buckets:
            name: str = bucket["Name"]

            # --- Public Access Block ---
            needs_pab_fix = False
            try:
                pab = s3.get_public_access_block(Bucket=name)
                conf = pab["PublicAccessBlockConfiguration"]
                required_keys = [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]
                if not all(conf.get(k, False) for k in required_keys):
                    needs_pab_fix = True
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                needs_pab_fix = True
            except botocore.exceptions.ClientError as exc:
                logger.warning("Could not check PAB for bucket %s: %s", name, exc)

            if needs_pab_fix:
                # Capture bucket name and client in closure for post-scan dispatch.
                def _make_s3_pab_remediator(s3_client, bucket):
                    def _remediator(finding):
                        self._remediate_s3_pab(s3_client, bucket, finding)
                    return _remediator

                self._log(
                    "MEDIUM",
                    "S3 Public Access Block not fully enabled",
                    name,
                    remediation="Enable all four Block Public Access options on the bucket.",
                    remediator=_make_s3_pab_remediator(s3, name),
                )

            # --- Bucket ACL ---
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee_uri = grant.get("Grantee", {}).get("URI", "")
                    if grantee_uri == "http://acs.amazonaws.com/groups/global/AllUsers":
                        self._log(
                            "HIGH",
                            "Publicly accessible S3 bucket (ACL)",
                            name,
                            remediation="Remove 'Everyone'/'AllUsers' from the bucket ACL.",
                        )
            except botocore.exceptions.ClientError as exc:
                logger.warning("Could not read ACL for bucket %s: %s", name, exc)

    def _remediate_s3_pab(self, s3_client, bucket_name: str, finding: dict) -> None:
        """Interactive prompt to apply Block Public Access to a single bucket."""
        print(f"\n  ⚠️  Bucket '{bucket_name}' is missing Public Access Blocks.")
        choice = input(f"  🛠️  Apply Block Public Access to '{bucket_name}'? (y/N): ")
        if choice.strip().lower() == "y":
            try:
                s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                )
                logger.info("✅ Block Public Access enabled for '%s'.", bucket_name)
                finding["title"] += " (REMEDIATED)"
                finding["severity"] = "LOW"
                finding["score"] = 1
            except botocore.exceptions.ClientError as exc:
                logger.error("Failed to remediate bucket '%s': %s", bucket_name, exc)
        else:
            print("  ⏭️  Skipped.")

    def scan_security_groups(self) -> None:
        """Check security groups for world-open inbound rules on sensitive ports."""
        logger.info("🔍 Scanning Security Groups...")

        def _scan_region(region: str) -> None:
            ec2 = self.session.client("ec2", region_name=region)
            try:
                sgs = self._paginate(ec2, "describe_security_groups", "SecurityGroups")
                for sg in sgs:
                    sg_id: str = sg["GroupId"]
                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        for ipr in perm.get("IpRanges", []):
                            if ipr.get("CidrIp") == "0.0.0.0/0":
                                if from_port is None or from_port in self.risky_ports:
                                    self._log(
                                        "HIGH",
                                        f"World-open Security Group (port {from_port or 'all'})",
                                        sg_id,
                                        region=region,
                                        remediation=(
                                            "EC2 → Security Groups → Edit inbound rules → "
                                            "Change source from 0.0.0.0/0 to a specific IP or SG."
                                        ),
                                    )
            except botocore.exceptions.ClientError as exc:
                logger.warning("Security group scan failed in %s: %s", region, exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
            pool.map(_scan_region, self.regions)

    def scan_iam(self) -> None:
        """Check IAM users for overly permissive policies and stale access keys."""
        logger.info("🔍 Scanning IAM...")
        iam = self.session.client("iam")
        try:
            users = self._paginate(iam, "list_users", "Users")
        except botocore.exceptions.ClientError as exc:
            logger.error("IAM scan error: %s", exc)
            return

        for user in users:
            name: str = user["UserName"]

            # Admin policy check
            try:
                policies = self._paginate(
                    iam, "list_attached_user_policies", "AttachedPolicies", UserName=name
                )
                for policy in policies:
                    if "AdministratorAccess" in policy["PolicyName"]:
                        self._log(
                            "HIGH",
                            "User has AdministratorAccess policy",
                            name,
                            remediation=(
                                "IAM → Users → Permissions → Detach AdministratorAccess. "
                                "Apply a least-privilege policy instead."
                            ),
                        )
            except botocore.exceptions.ClientError as exc:
                logger.warning("Could not list policies for user %s: %s", name, exc)

            # Stale access key check
            try:
                keys = self._paginate(
                    iam, "list_access_keys", "AccessKeyMetadata", UserName=name
                )
                now = datetime.datetime.now(datetime.timezone.utc)
                for key in keys:
                    age_days = (now - key["CreateDate"]).days
                    if age_days > self.key_age_days:
                        self._log(
                            "MEDIUM",
                            f"Access key older than {self.key_age_days} days ({age_days}d)",
                            f"{name}/{key['AccessKeyId']}",
                            remediation=(
                                "IAM → Users → Security credentials → "
                                "Delete or rotate old access keys."
                            ),
                        )
            except botocore.exceptions.ClientError as exc:
                logger.warning("Could not list access keys for user %s: %s", name, exc)

    def scan_ec2(self) -> None:
        """Check EC2 instances for public IPs and user-data secrets."""
        logger.info("🔍 Scanning EC2 instances...")

        def _scan_region(region: str) -> None:
            ec2 = self.session.client("ec2", region_name=region)
            # Construct the filter locally per thread — do not share mutable
            # objects across threads. Use "instance-state-name" (hyphen) which
            # is the canonical form accepted by all regions; the dot variant
            # ("instance-state.name") is deprecated and rejected in several
            # newer opt-in regions (e.g. ap-southeast-3, me-south-1).
            ec2_filters = [{"Name": "instance-state-name", "Values": ["running"]}]
            try:
                reservations = self._paginate(
                    ec2,
                    "describe_instances",
                    "Reservations",
                    Filters=ec2_filters,
                )
                for res in reservations:
                    for inst in res["Instances"]:
                        instance_id: str = inst["InstanceId"]

                        if inst.get("PublicIpAddress"):
                            self._log(
                                "MEDIUM",
                                "EC2 instance with public IP",
                                instance_id,
                                region=region,
                                remediation=(
                                    "Move instance to private subnet and use Systems Manager "
                                    "Session Manager or a bastion host."
                                ),
                            )

                        try:
                            attr = ec2.describe_instance_attribute(
                                InstanceId=instance_id, Attribute="userData"
                            )
                            user_data = attr.get("UserData", {})
                            if user_data and user_data.get("Value"):
                                self._log(
                                    "MEDIUM",
                                    "EC2 instance has User Data (review for secrets)",
                                    instance_id,
                                    region=region,
                                    remediation=(
                                        "Review User Data for embedded secrets. "
                                        "Use AWS Secrets Manager or SSM Parameter Store instead."
                                    ),
                                )
                        except botocore.exceptions.ClientError as exc:
                            logger.debug(
                                "Could not read user-data for %s: %s", instance_id, exc
                            )
            except botocore.exceptions.ClientError as exc:
                logger.warning("EC2 scan failed in %s: %s", region, exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
            pool.map(_scan_region, self.regions)

    def scan_lambda(self) -> None:
        """Check Lambda resource-based policies for wildcard principals."""
        logger.info("🔍 Scanning Lambda functions...")

        def _scan_region(region: str) -> None:
            lm = self.session.client("lambda", region_name=region)
            try:
                functions = self._paginate(lm, "list_functions", "Functions")
                for func in functions:
                    func_name: str = func["FunctionName"]
                    try:
                        raw_policy = lm.get_policy(FunctionName=func_name)
                        policy = json.loads(raw_policy.get("Policy", "{}"))
                        for stmt in policy.get("Statement", []):
                            principal = stmt.get("Principal", {})
                            # Principal can be "*" or {"AWS": "*"} or {"Service": "..."}
                            is_wildcard = principal == "*" or (
                                isinstance(principal, dict)
                                and any(v == "*" for v in principal.values())
                            )
                            if is_wildcard:
                                self._log(
                                    "HIGH",
                                    "Lambda function has public invoke permission",
                                    func_name,
                                    region=region,
                                    remediation=(
                                        "Lambda → Configuration → Permissions → "
                                        "Resource-based policy → Remove wildcard (*) principal."
                                    ),
                                )
                                break
                    except lm.exceptions.ResourceNotFoundException:
                        pass  # No resource policy — expected and safe
                    except botocore.exceptions.ClientError as exc:
                        logger.debug("Policy check failed for %s: %s", func_name, exc)
            except botocore.exceptions.ClientError as exc:
                logger.warning("Lambda scan failed in %s: %s", region, exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
            pool.map(_scan_region, self.regions)

    def scan_rds(self) -> None:
        """Check RDS instances for public accessibility."""
        logger.info("🔍 Scanning RDS databases...")

        def _scan_region(region: str) -> None:
            rds = self.session.client("rds", region_name=region)
            try:
                instances = self._paginate(rds, "describe_db_instances", "DBInstances")
                for db in instances:
                    if db.get("PubliclyAccessible"):
                        self._log(
                            "HIGH",
                            "RDS instance is publicly accessible",
                            db["DBInstanceIdentifier"],
                            region=region,
                            remediation=(
                                "RDS Console → Modify → Connectivity → "
                                "Set Public access to 'No'."
                            ),
                        )
            except botocore.exceptions.ClientError as exc:
                logger.warning("RDS scan failed in %s: %s", region, exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
            pool.map(_scan_region, self.regions)

    def scan_ebs_snapshots(self) -> None:
        """Check EBS snapshots for public create-volume permissions."""
        logger.info("🔍 Scanning EBS snapshots...")

        def _scan_region(region: str) -> None:
            ec2 = self.session.client("ec2", region_name=region)
            try:
                snapshots = self._paginate(
                    ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]
                )
                for snap in snapshots:
                    snap_id: str = snap["SnapshotId"]
                    try:
                        # CreateVolumePermission is NOT in describe_snapshots —
                        # it requires a dedicated attribute call.
                        attr = ec2.describe_snapshot_attribute(
                            SnapshotId=snap_id, Attribute="createVolumePermission"
                        )
                        perms = attr.get("CreateVolumePermissions", [])
                        if any(p.get("Group") == "all" for p in perms):
                            self._log(
                                "HIGH",
                                "Public EBS snapshot",
                                snap_id,
                                region=region,
                                remediation=(
                                    "EC2 → Snapshots → Modify permissions → "
                                    "Remove public access."
                                ),
                            )
                    except botocore.exceptions.ClientError as exc:
                        logger.debug(
                            "Could not check permissions for snapshot %s: %s", snap_id, exc
                        )
            except botocore.exceptions.ClientError as exc:
                logger.warning("EBS snapshot scan failed in %s: %s", region, exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
            pool.map(_scan_region, self.regions)

    def scan_kms(self) -> None:
        """Check KMS keys for disabled automatic rotation."""
        logger.info("🔍 Scanning KMS keys...")

        def _scan_region(region: str) -> None:
            kms = self.session.client("kms", region_name=region)
            try:
                keys = self._paginate(kms, "list_keys", "Keys")
                for key in keys:
                    key_id: str = key["KeyId"]
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get("KeyRotationEnabled", False):
                            self._log(
                                "MEDIUM",
                                "KMS key rotation disabled",
                                key_id,
                                region=region,
                                remediation=(
                                    "KMS Console → Select key → "
                                    "Enable automatic key rotation."
                                ),
                            )
                    except botocore.exceptions.ClientError as exc:
                        # AWS-managed keys raise UnsupportedOperationException
                        logger.debug("KMS rotation check skipped for %s: %s", key_id, exc)
            except botocore.exceptions.ClientError as exc:
                logger.warning("KMS scan failed in %s: %s", region, exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
            pool.map(_scan_region, self.regions)

    def scan_cloudtrail(self) -> None:
        """Check CloudTrail for trail existence and multi-region coverage."""
        logger.info("🔍 Scanning CloudTrail...")
        ct = self.session.client("cloudtrail")
        try:
            trails = ct.describe_trails().get("trailList", [])
            if not trails:
                self._log(
                    "HIGH",
                    "No CloudTrail trails configured",
                    "Global",
                    remediation=(
                        "CloudTrail Console → Create a new multi-region trail "
                        "with logging enabled."
                    ),
                )
            elif not any(t.get("IsMultiRegionTrail", False) for t in trails):
                self._log(
                    "MEDIUM",
                    "CloudTrail not configured as multi-region",
                    "Global",
                    remediation="Edit trail and enable 'Apply trail to all regions'.",
                )
        except botocore.exceptions.ClientError as exc:
            logger.error("CloudTrail scan error: %s", exc)

    # ------------------------------------------------------------------
    # AI summary
    # ------------------------------------------------------------------

    def _get_gemini_api_key(self) -> Optional[str]:
        """Fetch (and cache) the Gemini API key from AWS Secrets Manager."""
        if self._gemini_api_key:
            return self._gemini_api_key

        logger.info("🔑 Retrieving API key from AWS Secrets Manager...")
        region = self.session.region_name or self.regions[0]
        client = self.session.client("secretsmanager", region_name=region)
        try:
            response = client.get_secret_value(SecretId=self.secret_name)
            secret = json.loads(response["SecretString"])
            self._gemini_api_key = secret.get("GEMINI_API_KEY")
            return self._gemini_api_key
        except botocore.exceptions.ClientError as exc:
            logger.warning("Failed to retrieve secret '%s': %s", self.secret_name, exc)
            return None
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Secret format unexpected: %s", exc)
            return None

    def generate_ai_executive_summary(self) -> str:
        """Generate an HTML executive summary using Google Gemini."""
        api_key = self._get_gemini_api_key()
        if not api_key:
            return (
                "<p style='color:salmon'>AI Summary unavailable: "
                "could not retrieve API key from AWS Secrets Manager.</p>"
            )

        if not self.findings:
            return (
                "<p style='color:lightgreen'>No vulnerabilities found. "
                "The AWS environment appears secure.</p>"
            )

        logger.info("🧠 Generating AI Executive Summary via Google Gemini...")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(GEMINI_MODEL)

        # Only pass severity + sanitized title — never pass raw resource names
        # (which could contain prompt-injection payloads) directly.
        summary_data = [
            {"severity": f["severity"], "issue": f["title"]}
            for f in self.findings
        ]

        prompt = (
            "You are an expert AWS Cloud Security Architect. "
            "Review the following JSON list of security findings from an AWS account:\n\n"
            f"{json.dumps(summary_data, indent=2)}\n\n"
            "Write a concise, professional Executive Summary for a CTO. "
            "Format it using HTML tags (<b>, <p>, <ul>, <li>) only — "
            "no Markdown, no ```html blocks. Focus on:\n"
            "1. Overall security posture.\n"
            "2. The most critical risks needing immediate attention.\n"
            "3. A brief strategic remediation recommendation."
        )

        try:
            response = model.generate_content(prompt)
            return response.text.strip()
        except Exception as exc:  # Gemini SDK may raise various types
            logger.warning("AI generation failed: %s", exc)
            return f"<p style='color:salmon'>AI Summary generation failed: {html.escape(str(exc))}</p>"

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def generate_html_report(self, ai_summary_html: str) -> str:
        """Build and write an interactive HTML security report. Returns the path."""
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")
        total = len(self.findings)
        risk_score = round((high * 3 + medium * 2 + low) / max(total, 1) * 33.3, 1)

        risk_color = (
            "text-red-400" if risk_score > 60
            else "text-orange-400" if risk_score > 30
            else "text-green-400"
        )
        bar_color = (
            "bg-red-500" if risk_score > 60
            else "bg-orange-500" if risk_score > 30
            else "bg-green-500"
        )

        # Build finding rows — ALL values HTML-escaped before insertion
        rows_html = ""
        for finding in sorted(self.findings, key=lambda x: x["score"], reverse=True):
            color = (
                "text-red-400" if finding["severity"] == "HIGH"
                else "text-orange-400" if finding["severity"] == "MEDIUM"
                else "text-yellow-400"
            )
            rows_html += f"""
                <tr class="finding-row border-t border-slate-700">
                    <td class="py-5 px-6 font-bold {color}">{html.escape(finding['severity'])}</td>
                    <td class="py-5 px-6 font-medium">{html.escape(finding['title'])}</td>
                    <td class="py-5 px-6 text-slate-300">{html.escape(finding['resource'])}</td>
                    <td class="py-5 px-6 text-slate-400">{html.escape(finding['region'])}</td>
                    <td class="py-5 px-6 text-slate-300 text-sm">{html.escape(finding.get('remediation', 'Review in AWS Console'))}</td>
                </tr>"""

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Scan Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        body {{ background: #0f172a; color: #e2e8f0; }}
        .finding-row {{ transition: all 0.2s; }}
        .finding-row:hover {{ background-color: #1e2937; transform: scale(1.005); }}
        .ai-content p {{ margin-bottom: 0.75rem; }}
        .ai-content ul {{ list-style-type: disc; margin-left: 1.5rem; margin-bottom: 0.75rem; }}
    </style>
</head>
<body class="min-h-screen p-6">
<div class="max-w-7xl mx-auto">

    <!-- Header -->
    <div class="flex justify-between items-center mb-8">
        <div>
            <h1 class="text-4xl font-bold text-blue-400 flex items-center gap-3">
                <i class="fas fa-shield-alt"></i> AWS Security Scanner
            </h1>
            <p class="text-slate-400 mt-1">Cloud Security Posture Report &mdash; {timestamp}</p>
        </div>
        <button onclick="window.print()"
                class="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded-lg flex items-center gap-2">
            <i class="fas fa-print"></i> Print Report
        </button>
    </div>

    <!-- Summary cards -->
    <div class="grid grid-cols-1 md:grid-cols-5 gap-6 mb-10">
        <div class="bg-slate-800 p-6 rounded-2xl">
            <div class="text-slate-400 text-sm">Overall Risk Score</div>
            <div class="text-5xl font-bold mt-2 {risk_color}">{risk_score}</div>
            <div class="w-full bg-slate-700 h-2 rounded mt-4">
                <div class="h-2 rounded {bar_color}" style="width:{min(risk_score,100)}%"></div>
            </div>
        </div>
        <div class="bg-slate-800 p-6 rounded-2xl flex items-center justify-between">
            <i class="fas fa-exclamation-triangle text-red-400 text-2xl"></i>
            <div class="text-right">
                <div class="text-4xl font-bold text-red-400">{high}</div>
                <div class="text-sm text-slate-400">High</div>
            </div>
        </div>
        <div class="bg-slate-800 p-6 rounded-2xl flex items-center justify-between">
            <i class="fas fa-exclamation-circle text-orange-400 text-2xl"></i>
            <div class="text-right">
                <div class="text-4xl font-bold text-orange-400">{medium}</div>
                <div class="text-sm text-slate-400">Medium</div>
            </div>
        </div>
        <div class="bg-slate-800 p-6 rounded-2xl flex items-center justify-between">
            <i class="fas fa-info-circle text-yellow-400 text-2xl"></i>
            <div class="text-right">
                <div class="text-4xl font-bold text-yellow-400">{low}</div>
                <div class="text-sm text-slate-400">Low</div>
            </div>
        </div>
        <div class="bg-slate-800 p-6 rounded-2xl flex items-center justify-center">
            <div class="text-center">
                <div class="text-5xl font-bold">{total}</div>
                <div class="text-slate-400">Total Findings</div>
            </div>
        </div>
    </div>

    <!-- AI Executive Summary -->
    <div class="bg-gradient-to-r from-indigo-900 to-slate-800 p-8 rounded-3xl mb-10
                border border-indigo-500/30 shadow-lg shadow-indigo-500/10">
        <h2 class="text-2xl font-bold text-indigo-300 mb-4 flex items-center gap-2">
            <i class="fas fa-robot"></i> AI Executive Summary
        </h2>
        <div class="text-slate-200 leading-relaxed ai-content">
            {ai_summary_html}
        </div>
    </div>

    <!-- Filters -->
    <div class="flex flex-col md:flex-row gap-4 mb-6">
        <input type="text" id="searchInput" onkeyup="filterTable()"
               placeholder="Search findings..."
               class="flex-1 bg-slate-800 border border-slate-600 rounded-xl px-5 py-3
                      focus:outline-none focus:border-blue-500">
        <div class="flex gap-3">
            <button onclick="filterBySeverity('all')"
                    class="px-5 py-3 bg-slate-700 hover:bg-slate-600 rounded-xl">All</button>
            <button onclick="filterBySeverity('HIGH')"
                    class="px-5 py-3 bg-red-900/30 hover:bg-red-900/50 text-red-400 rounded-xl">High</button>
            <button onclick="filterBySeverity('MEDIUM')"
                    class="px-5 py-3 bg-orange-900/30 hover:bg-orange-900/50 text-orange-400 rounded-xl">Medium</button>
            <button onclick="filterBySeverity('LOW')"
                    class="px-5 py-3 bg-yellow-900/30 hover:bg-yellow-900/50 text-yellow-400 rounded-xl">Low</button>
        </div>
    </div>

    <!-- Findings table -->
    <div class="bg-slate-800 rounded-3xl overflow-hidden">
        <table class="w-full" id="findingsTable">
            <thead>
                <tr class="bg-slate-900">
                    <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(0)">Severity</th>
                    <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(1)">Title</th>
                    <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(2)">Resource</th>
                    <th class="py-5 px-6 text-left cursor-pointer" onclick="sortTable(3)">Region</th>
                    <th class="py-5 px-6 text-left">Remediation</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>

    <div class="text-center text-slate-500 text-sm mt-10">
        Generated by AWS Security Scanner &mdash; Agentless &mdash; {timestamp}
    </div>
</div>

<script>
    function filterTable() {{
        const q = document.getElementById('searchInput').value.toLowerCase();
        document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
            row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
        }});
    }}

    function filterBySeverity(sev) {{
        document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
            row.style.display = (sev === 'all' || row.cells[0].textContent.trim() === sev) ? '' : 'none';
        }});
    }}

    function sortTable(col) {{
        const tbody = document.querySelector('#findingsTable tbody');
        const rows = Array.from(tbody.rows);
        let asc = tbody.dataset.sortCol === String(col) && tbody.dataset.sortDir === 'asc';
        rows.sort((a, b) =>
            a.cells[col].textContent.localeCompare(b.cells[col].textContent) * (asc ? -1 : 1)
        );
        tbody.dataset.sortCol = col;
        tbody.dataset.sortDir = asc ? 'desc' : 'asc';
        rows.forEach(r => tbody.appendChild(r));
    }}
</script>
</body>
</html>"""

        path = os.path.join(self.output_dir, "aws-security-report.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report_html)
        logger.info("📄 HTML report written: %s", path)
        return path

    # ------------------------------------------------------------------
    # Remediation summary gate
    # ------------------------------------------------------------------

    def _prompt_remediation_summary(self) -> list[dict]:
        """
        Show a consolidated list of un-remediated HIGH/MEDIUM findings and ask
        for confirmation before touching anything.

        Returns the list of findings the user has approved for remediation,
        or an empty list if the user declines or there is nothing to act on.
        """
        # Only include findings that have a known automated remediator and have
        # not already been marked as REMEDIATED during a previous run.
        remediable = [
            f for f in self.findings
            if f["severity"] in ("HIGH", "MEDIUM")
            and "REMEDIATED" not in f["title"]
            and f.get("remediator")  # only findings that have a handler registered
        ]
        if not remediable:
            logger.info("No actionable findings for automated remediation.")
            return []

        print("\n" + "=" * 60)
        print(f"  REMEDIATION SUMMARY — {len(remediable)} finding(s) can be addressed")
        print("=" * 60)
        for i, f in enumerate(remediable, 1):
            print(f"  {i}. [{f['severity']}] {f['title']} → {f['resource']} ({f['region']})")
        print("=" * 60)
        choice = input("Proceed with interactive per-finding remediation? (y/N): ")
        return remediable if choice.strip().lower() == "y" else []

    # ------------------------------------------------------------------
    # Full scan orchestration
    # ------------------------------------------------------------------

    def run_full_scan(self) -> None:
        """Execute all scan modules and produce JSON + HTML reports."""
        logger.info("🚀 Starting AWS Security Scanner...")

        self.scan_s3()
        self.scan_security_groups()
        self.scan_iam()
        self.scan_ec2()
        self.scan_lambda()
        self.scan_rds()
        self.scan_ebs_snapshots()
        self.scan_kms()
        self.scan_cloudtrail()

        logger.info("✅ Scan complete — %d finding(s) recorded.", len(self.findings))

        self.findings.sort(key=lambda x: x["score"], reverse=True)

        # --- JSON report (strip non-serialisable remediator callables) ---
        json_path = os.path.join(self.output_dir, "aws-security-report.json")
        serialisable_findings = [
            {k: v for k, v in f.items() if k != "remediator"}
            for f in self.findings
        ]
        report = {
            "scanner": "AWS Security Scanner",
            "timestamp": datetime.datetime.now().isoformat(),
            "summary": {
                "total": len(self.findings),
                "high": sum(1 for f in self.findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
                "low": sum(1 for f in self.findings if f["severity"] == "LOW"),
            },
            "findings": serialisable_findings,
        }
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        logger.info("📄 JSON report written: %s", json_path)

        # --- AI summary — generated once, reused for any post-remediation ---
        # report refresh. The summary reflects findings as discovered; it does
        # not need to change because a fix was applied.
        ai_html = self.generate_ai_executive_summary()

        # --- HTML report (initial snapshot) ---
        self.generate_html_report(ai_html)

        # --- Top findings ---
        logger.info("\n🔥 Top 10 findings:")
        for f in self.findings[:10]:
            logger.info("   %s | %s → %s", f["severity"], f["title"], f["resource"])

        # --- Remediation phase (post-scan, after reports are written) ---
        if self.remediate:
            approved = self._prompt_remediation_summary()
            if approved:
                logger.info("🛠️  Starting remediation phase...")
                for finding in approved:
                    finding["remediator"](finding)
                logger.info("Remediation phase complete.")
                # Regenerate HTML only — reuse the cached ai_html so the
                # Gemini API is not called a second time.
                self.findings.sort(key=lambda x: x["score"], reverse=True)
                self.generate_html_report(ai_html)
                logger.info("📄 Reports updated with remediation status.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS Security Scanner — agentless multi-service posture scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--profile", help="AWS CLI profile name", default=None)
    parser.add_argument(
        "--regions",
        help="Comma-separated list of AWS regions to scan (default: all enabled regions)",
        default=None,
    )
    parser.add_argument(
        "--remediate",
        help="Enable interactive automated remediation after the scan completes",
        action="store_true",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for report output files",
        default=DEFAULT_OUTPUT_DIR,
    )
    parser.add_argument(
        "--secret-name",
        help="AWS Secrets Manager secret name holding the GEMINI_API_KEY",
        default=DEFAULT_SECRET_NAME,
    )
    parser.add_argument(
        "--key-age-days",
        help="Flag IAM access keys older than this many days",
        type=int,
        default=DEFAULT_KEY_AGE_DAYS,
    )
    parser.add_argument(
        "--risky-ports",
        help="Comma-separated list of ports to flag when open to 0.0.0.0/0",
        default=None,
    )
    args = parser.parse_args()

    regions = args.regions.split(",") if args.regions else None
    risky_ports = (
        [int(p) for p in args.risky_ports.split(",")]
        if args.risky_ports
        else None
    )

    scanner = AWSSecurityScanner(
        profile=args.profile,
        regions=regions,
        remediate=args.remediate,
        output_dir=args.output_dir,
        secret_name=args.secret_name,
        risky_ports=risky_ports,
        key_age_days=args.key_age_days,
    )
    scanner.run_full_scan()


if __name__ == "__main__":
    main()