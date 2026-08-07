#!/usr/bin/env python3
"""Dependency-free Terraform/OpenTofu baseline checks for GitHub pull requests."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
from urllib import error, request


SENSITIVE_PORTS = {22, 3389, 5432, 3306, 27017}
MARKER = "<!-- vancer-baseline-checker -->"
CTA = "Powered by [Vancer Baseline One](https://vancerbaseline.netlify.app/). Enterprise-grade SOC 2 & GDPR AWS infrastructure."
IAM_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy", "aws_iam_user_policy"}


@dataclass(frozen=True)
class Block:
    kind: str
    labels: tuple[str, ...]
    text: str
    start_line: int
    body_offset: int


@dataclass(frozen=True)
class Violation:
    rule: str
    file: str
    line: int
    message: str
    remediation: str


def line_at(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def closing_brace(text: str, opening: int) -> Optional[int]:
    """Return the matching brace while ignoring strings and Terraform comments."""
    depth, index, quote = 0, opening, None
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if char == "\\\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == "#":
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline
            continue
        elif char == "/" and following == "/":
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline
            continue
        elif char == "/" and following == "*":
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def blocks(text: str, kind: Optional[str] = None) -> list[Block]:
    """Extract named HCL blocks with enough structure for conservative checks."""
    pattern = re.compile(r"(?m)^\s*([A-Za-z_][\w-]*)(?:\s+\"([^\"]+)\")?(?:\s+\"([^\"]+)\")?\s*\{")
    result: list[Block] = []
    for match in pattern.finditer(text):
        block_kind = match.group(1)
        if kind and block_kind != kind:
            continue
        end = closing_brace(text, match.end() - 1)
        if end is None:
            continue
        labels = tuple(value for value in match.groups()[1:] if value is not None)
        result.append(Block(block_kind, labels, text[match.start():end + 1], line_at(text, match.start()), match.end()))
    return result


def resource_blocks(text: str) -> list[Block]:
    return [block for block in blocks(text, "resource") if len(block.labels) == 2]


def first_match_line(block: Block, pattern: str) -> int:
    match = re.search(pattern, block.text, re.IGNORECASE | re.MULTILINE)
    return block.start_line + block.text.count("\n", 0, match.start()) if match else block.start_line


def is_true(text: str, attribute: str) -> bool:
    return bool(re.search(r"(?mi)^\s*" + re.escape(attribute) + r"\s*=\s*true\b", text))


def value_exists(text: str, attribute: str) -> bool:
    return bool(re.search(r"(?mi)^\s*" + re.escape(attribute) + r"\s*=\s*[^\s#]+", text))


def public_access_block_protects(bucket_name: str, resources: Iterable[Block]) -> bool:
    reference = re.compile(r"(?m)^\s*bucket\s*=\s*(?:aws_s3_bucket\.)?" + re.escape(bucket_name) + r"(?:\.id)?\s*(?:#.*)?$")
    for candidate in resources:
        if candidate.labels[0] != "aws_s3_bucket_public_access_block":
            continue
        if reference.search(candidate.text) and all(is_true(candidate.text, key) for key in (
            "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"
        )):
            return True
    return False


def has_public_cidr(text: str) -> bool:
    return bool(re.search(r'(?s)(?:cidr_blocks|cidr_ipv4)\s*=\s*[^\n]*(?:\[\s*)?"0\.0\.0\.0/0"', text))


def exposed_sensitive_port(text: str) -> bool:
    for match in re.finditer(r"(?mi)^\s*(?:from_port|to_port)\s*=\s*(\d+)\s*$", text):
        if int(match.group(1)) in SENSITIVE_PORTS:
            return True
    return False


def scan_file(path: Path, relative_path: str) -> list[Violation]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="replace")
    findings: list[Violation] = []
    resources = resource_blocks(text)

    for resource in resources:
        resource_type, resource_name = resource.labels
        if resource_type == "aws_s3_bucket":
            if re.search(r'(?mi)^\s*acl\s*=\s*"public-read(?:-write)?"', resource.text):
                findings.append(Violation("S3_PUBLIC_ACL", relative_path, first_match_line(resource, r"acl\s*="),
                    "S3 bucket grants a public ACL.", "Remove the public ACL and use private access controls."))
            if not public_access_block_protects(resource_name, resources):
                findings.append(Violation("S3_MISSING_PUBLIC_ACCESS_BLOCK", relative_path, resource.start_line,
                    "S3 bucket has no explicit, fully enabled public-access block.",
                    "Add aws_s3_bucket_public_access_block with all four block settings set to true."))

        if resource_type == "aws_ebs_volume" and not is_true(resource.text, "encrypted"):
            findings.append(Violation("EBS_ENCRYPTION_DISABLED", relative_path, resource.start_line,
                "EBS volume does not explicitly enable encryption.", "Set encrypted = true and provide a customer-managed kms_key_id."))

        if resource_type == "aws_db_instance" and not is_true(resource.text, "storage_encrypted") and not is_true(resource.text, "encrypted"):
            findings.append(Violation("RDS_ENCRYPTION_DISABLED", relative_path, resource.start_line,
                "DB instance does not explicitly enable storage encryption.", "Set storage_encrypted = true and configure kms_key_id."))

        if resource_type == "aws_s3_bucket_server_side_encryption_configuration":
            has_kms = value_exists(resource.text, "kms_master_key_id") or value_exists(resource.text, "kms_key_id")
            uses_kms = bool(re.search(r'(?mi)^\s*sse_algorithm\s*=\s*"aws:kms"', resource.text))
            if not (has_kms and uses_kms):
                findings.append(Violation("S3_CUSTOMER_MANAGED_ENCRYPTION_MISSING", relative_path, resource.start_line,
                    "S3 server-side encryption is not configured with a customer-managed KMS key.",
                    "Use sse_algorithm = \"aws:kms\" and set kms_master_key_id."))

        if resource_type == "aws_security_group":
            for ingress in blocks(resource.text, "ingress"):
                if has_public_cidr(ingress.text) and exposed_sensitive_port(ingress.text):
                    findings.append(Violation("PUBLIC_SENSITIVE_INGRESS", relative_path,
                        resource.start_line + ingress.start_line - 1,
                        "Security group exposes a sensitive port to the public internet.",
                        "Restrict the source CIDR to trusted networks or remove the ingress rule."))
        elif resource_type == "aws_vpc_security_group_ingress_rule" and has_public_cidr(resource.text) and exposed_sensitive_port(resource.text):
            findings.append(Violation("PUBLIC_SENSITIVE_INGRESS", relative_path, resource.start_line,
                "Security group ingress rule exposes a sensitive port to the public internet.",
                "Restrict cidr_ipv4 to trusted networks or remove the ingress rule."))

        if resource_type in IAM_TYPES:
            wildcard_action = bool(re.search(r'(?is)["\']?Action["\']?\s*(?:=|:)\s*(?:\[\s*)?["\']\*["\']', resource.text))
            wildcard_resource = bool(re.search(r'(?is)["\']?Resource["\']?\s*(?:=|:)\s*(?:\[\s*)?["\']\*["\']', resource.text))
            if wildcard_action and wildcard_resource:
                findings.append(Violation("IAM_ADMIN_WILDCARD", relative_path, resource.start_line,
                    "IAM policy grants wildcard action and wildcard resource access.",
                    "Scope actions and resources to the least privilege required."))
    return findings


def changed_infrastructure_files(event: dict) -> list[str]:
    pull_request = event.get("pull_request")
    if not pull_request:
        return []
    base = pull_request.get("base", {}).get("sha")
    head = pull_request.get("head", {}).get("sha")
    if not base or not head:
        raise RuntimeError("Pull request event does not include base and head commit SHAs.")
    command = ["git", "diff", "--name-only", "--diff-filter=ACMR", base, head]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise RuntimeError("Unable to determine changed files with git diff. Ensure checkout fetch-depth is 0.")
    return [name for name in completed.stdout.splitlines() if name.lower().endswith((".tf", ".tofu"))]


def github_request(method: str, url: str, token: str, data: Optional[dict] = None) -> object:
    payload = json.dumps(data).encode("utf-8") if data is not None else None
    req = request.Request(url, data=payload, method=method, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "vancer-baseline-checker"
    })
    with request.urlopen(req, timeout=15) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else None


def report(findings: list[Violation], files_scanned: int) -> str:
    header = f"{MARKER}\n## 🛡️ Vancer Baseline Security Gate\n\n"
    if not findings:
        return header + f"✅ No critical baseline violations found in {files_scanned} changed Terraform/OpenTofu file(s).\n\n{CTA}"
    rows = ["| Rule | File | Line | Finding | Recommended fix |", "| --- | --- | ---: | --- | --- |"]
    for item in findings:
        safe_message = item.message.replace("|", "\\|")
        safe_fix = item.remediation.replace("|", "\\|")
        rows.append(f"| `{item.rule}` | `{item.file}` | {item.line} | {safe_message} | {safe_fix} |")
    return header + "❌ Critical baseline violations were found.\n\n" + "\n".join(rows) + f"\n\n{CTA}"


def publish_report(event: dict, token: str, body: str) -> None:
    if not token or not event.get("pull_request"):
        return
    repository = event.get("repository", {}).get("full_name")
    number = event["pull_request"].get("number") or event.get("number")
    if not repository or not number:
        raise RuntimeError("Pull request event does not include repository or pull request number.")
    root = f"https://api.github.com/repos/{repository}/issues/{number}/comments"
    comments = github_request("GET", root, token)
    existing = next((item for item in comments if MARKER in item.get("body", "") and item.get("user", {}).get("type") == "Bot"), None)
    if existing:
        github_request("PATCH", f"{root}/{existing['id']}", token, {"body": body})
    else:
        github_request("POST", root, token, {"body": body})


def set_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def main() -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        print("Vancer Baseline Checker must run in a GitHub Actions event context.", file=sys.stderr)
        return 2
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        names = changed_infrastructure_files(event)
        findings: list[Violation] = []
        workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
        for name in names:
            candidate = (workspace / name).resolve()
            if workspace not in candidate.parents or not candidate.is_file():
                continue
            findings.extend(scan_file(candidate, name))
        body = report(findings, len(names))
        print(body)
        set_output("violations", str(len(findings)))
        set_output("changed_files", str(len(names)))
        if os.environ.get("INPUT_COMMENT_ON_PR", "true").lower() == "true":
            try:
                publish_report(event, os.environ.get("INPUT_GITHUB_TOKEN", ""), body)
            except (error.URLError, error.HTTPError, RuntimeError) as exc:
                print(f"Warning: unable to publish the pull request report: {exc}", file=sys.stderr)
        fail = os.environ.get("INPUT_FAIL_ON_VIOLATION", "true").lower() == "true"
        return 1 if findings and fail else 0
    except (OSError, ValueError, RuntimeError, error.URLError, error.HTTPError) as exc:
        print(f"Vancer Baseline Checker failed safely: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
