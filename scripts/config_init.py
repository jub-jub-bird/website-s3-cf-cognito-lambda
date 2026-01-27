#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


# -----------------------------
# Helpers
# -----------------------------
def repo_root_from_scripts_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def _clean_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = re.split(r"[/?#]", d, maxsplit=1)[0]
    d = re.sub(r":\d+$", "", d)
    if d.startswith("*."):
        d = d[2:]
    d = d.rstrip(".")
    return d


def domain_to_slug(domain: str) -> str:
    d = _clean_domain(domain)
    if not d or "." not in d:
        raise ValueError(f"Domain does not look valid: '{domain}'")
    d = re.sub(r"[^a-z0-9.\-]+", "-", d)
    d = re.sub(r"\.+", ".", d)
    d = re.sub(r"-{2,}", "-", d)
    slug = d.replace(".", "-").strip("-")
    if not slug:
        raise ValueError(f"Could not derive slug from domain: '{domain}'")
    return slug


def prompt_with_default(label: str, default: str, explain: str = "") -> str:
    if explain:
        print(explain)
    v = input(f"{label} [{default}]: ").strip()
    return v if v else default


def prompt_required(label: str, example: str, explain: str = "") -> str:
    if explain:
        print(explain)
    while True:
        v = input(f"{label} (e.g. {example}): ").strip()
        if v:
            return v


def write_text(path: Path, content: str, force: bool) -> bool:
    if path.exists() and not force:
        return False
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def _yaml_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_pulumi_project_yaml(project_name: str) -> str:
    lines: list[str] = []
    lines.append(f"name: {project_name}")
    lines.append("description: A minimal AWS Python Pulumi program")
    lines.append("runtime:")
    lines.append("  name: python")
    lines.append("  options:")
    lines.append("    toolchain: pip")
    lines.append("    virtualenv: .venv")
    lines.append("config:")
    lines.append("  pulumi:tags:")
    lines.append("    value:")
    lines.append("      pulumi:template: aws-python.....")
    lines.append("")
    return "\n".join(lines)


def build_sorted_config_yaml(values: dict[str, str], comments: dict[str, str]) -> str:
    lines: list[str] = ["config:"]
    for key in sorted(values.keys()):
        if key in comments:
            lines.append(f"  # {comments[key]}")
        lines.append(f"  {key}: {values[key]}")
    lines.append("")
    return "\n".join(lines)


# -----------------------------
# Stack YAML builders (no secrets)
# -----------------------------
def build_network_yaml(prefix: str, values: dict[str, str]) -> str:
    comments = {
        "aws:profile": "AWS CLI profile used by the Pulumi AWS provider",
        "aws:region": "AWS region for all resources in this stack",
        f"{prefix}:accountId": "AWS Account ID for the shared/network account",
        f"{prefix}:adoptExistingRecords": "False on first deploy; true to adopt existing Route 53 records",
        f"{prefix}:baseDomain": "Base/root DNS domain for the site",
        f"{prefix}:deployRoleName": "IAM role name Pulumi assumes when deploying into target accounts",
        f"{prefix}:domainSlug": "Slug used for naming AWS resources and Pulumi project",
        f"{prefix}:hostedZoneId": "Route 53 Hosted Zone ID for the base domain",
        f"{prefix}:hostedZoneName": "Route 53 Hosted Zone name for the base domain",
        f"{prefix}:org": "Pulumi organization name",
        f"{prefix}:protectDnsRecords": "Whether DNS records should be protected from deletion",
        f"{prefix}:pythonCmd": "Path to Python interpreter used by Pulumi for this project",
    }
    return build_sorted_config_yaml(values, comments)


def build_workload_yaml_no_secrets(prefix: str, values: dict[str, str], env: str) -> str:
    """
    Used for staging+prod.
    Secrets are intentionally NOT written here.
    """
    comments = {
        "aws-native:profile": "AWS CLI profile for aws-native provider",
        "aws-native:region": "Region for aws-native provider",
        "aws:profile": "AWS CLI profile used by the Pulumi AWS provider",
        "aws:region": "AWS region for this stack",
        f"{prefix}:accountId": f"AWS Account ID for the {env} account",
        f"{prefix}:authApiCustomDomain": f"Custom domain for the auth API ({env})",
        f"{prefix}:baseDomain": "Base/root DNS domain for the site",
        f"{prefix}:cognitoAuthDomain": f"Cognito auth domain ({env})",
        f"{prefix}:defaultRootObject": "Default object served by CloudFront",
        f"{prefix}:deployRoleName": "IAM role name Pulumi assumes when deploying into target accounts",
        f"{prefix}:domainSlug": "Slug used for naming AWS resources and Pulumi project",
        f"{prefix}:enableApiLogging": "Enable/disable API access logging",
        f"{prefix}:enableAuthApiDomain": "Enable the auth API custom domain (often false on first deploy)",
        f"{prefix}:enableCognitoDomain": "Enable the Cognito custom domain (often false on first deploy)",
        f"{prefix}:enableCustomDomain": "Enable the CloudFront custom domain (often false on first deploy)",
        f"{prefix}:logRetentionDays": "CloudWatch log retention (days)",
        f"{prefix}:org": "Pulumi organization name",
        f"{prefix}:pythonCmd": "Path to Python interpreter used by Pulumi for this project",
        f"{prefix}:redirectPath": "Path used for auth redirect callbacks",
    }
    return build_sorted_config_yaml(values, comments)


# -----------------------------
# Secrets injection (Pulumi CLI)
# -----------------------------
def _pulumi_run(args: list[str]) -> None:
    subprocess.run(args, check=True)


def _pulumi_config_set_from_stdin(key: str, value: str, secret: bool = False) -> None:
    """
    Multi-line safe: send value via stdin (PEMs, secrets).
    """
    args = ["pulumi", "config", "set", key]
    if secret:
        args.append("--secret")

    payload = value
    if not payload.endswith("\n"):
        payload += "\n"

    subprocess.run(args, input=payload, text=True, check=True)


def _load_secrets_json(repo_root: Path, base_domain: str, slug: str, env: str) -> dict:
    secrets_dir = repo_root / "secrets"
    candidates = [
        secrets_dir / f"{base_domain}-{env}.secrets.json",
        secrets_dir / f"{slug}-{env}.secrets.json",
    ]
    for p in candidates:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        "Could not find secrets JSON. Tried:\n" + "\n".join(f"  - {c}" for c in candidates)
    )


def _load_public_key_pem(repo_root: Path, base_domain: str, slug: str, env: str) -> str:
    secrets_dir = repo_root / "secrets"
    candidates = [
        secrets_dir / f"{base_domain}-{env}-public-key.pem",
        secrets_dir / f"{slug}-{env}-public-key.pem",
    ]
    for p in candidates:
        if p.exists():
            return p.read_text(encoding="utf-8")
    raise FileNotFoundError(
        "Could not find public key PEM. Tried:\n" + "\n".join(f"  - {c}" for c in candidates)
    )


def pulumi_inject_secrets_for_env(
    repo_root: Path,
    base_domain: str,
    slug: str,
    env: str,
    region: str,
    profile: str,
) -> None:
    stack = f"{slug}-{env}"
    prefix = slug

    secrets_obj = _load_secrets_json(repo_root, base_domain, slug, env)
    required = ["stateSecret", "originVerifySecret", "cloudfrontPrivateKeyPem"]
    missing = [k for k in required if not secrets_obj.get(k)]
    if missing:
        raise ValueError(f"Secrets JSON missing required keys: {missing}")

    state_secret = secrets_obj["stateSecret"]
    origin_verify_secret = secrets_obj["originVerifySecret"]
    cloudfront_private_key_pem = secrets_obj["cloudfrontPrivateKeyPem"]
    cloudfront_public_key_pem = _load_public_key_pem(repo_root, base_domain, slug, env)

    print(f"\n[Secrets Injection] Selecting stack: {stack}")
    _pulumi_run(["pulumi", "stack", "select", stack])

    # Provider config (plain)
    print("[Secrets Injection] Setting provider config (plain)...")
    _pulumi_run(["pulumi", "config", "set", "aws:region", region])
    _pulumi_run(["pulumi", "config", "set", "aws:profile", profile])
    _pulumi_run(["pulumi", "config", "set", "aws-native:region", region])
    _pulumi_run(["pulumi", "config", "set", "aws-native:profile", profile])

    # Public key (plain, via stdin because it's multi-line)
    print("[Secrets Injection] Setting CloudFront public key (plain via stdin)...")
    _pulumi_config_set_from_stdin(f"{prefix}:cloudfrontPublicKeyPem", cloudfront_public_key_pem, secret=False)

    # Secrets (secure, via stdin)
    print("[Secrets Injection] Setting secrets (secure via stdin)...")
    _pulumi_config_set_from_stdin(f"{prefix}:stateSecret", state_secret, secret=True)
    _pulumi_config_set_from_stdin(f"{prefix}:originVerifySecret", origin_verify_secret, secret=True)
    _pulumi_config_set_from_stdin(f"{prefix}:cloudfrontPrivateKeyPem", cloudfront_private_key_pem, secret=True)

    print("[Secrets Injection] Done.")


# -----------------------------
# Main
# -----------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize Pulumi stack YAMLs (network/staging/prod).")
    parser.add_argument("--domain", required=True, help="Domain name, e.g. example.com or example.co.uk")
    parser.add_argument("--region", help="AWS region (if omitted, you will be prompted). Example: eu-west-2")
    parser.add_argument("--profile", help="AWS CLI profile (if omitted, you will be prompted).")
    parser.add_argument("--force", action="store_true", help="Overwrite existing YAML files")
    parser.add_argument("--inject-secrets", action="store_true", help="Inject secrets into Pulumi stack config via CLI")
    parser.add_argument("--inject-envs", default="staging,prod", help="Comma-separated envs for secrets injection")
    args = parser.parse_args()

    root = repo_root_from_scripts_dir()
    base_domain = _clean_domain(args.domain)
    slug = domain_to_slug(args.domain)
    prefix = slug  # MUST match Pulumi.yaml name

    print("\n=== config_init.py ===")
    print("Creates exactly these three stack files:")
    print(f"  - Pulumi.{slug}-network.yaml")
    print(f"  - Pulumi.{slug}-staging.yaml")
    print(f"  - Pulumi.{slug}-prod.yaml")
    print("\nOptional: --inject-secrets will write secure: values into Pulumi.<stack>.yaml via Pulumi CLI.\n")

    region = prompt_with_default("Deploy region", args.region.strip() if args.region else "eu-west-2")
    profile = prompt_with_default("AWS profile", args.profile.strip() if args.profile else "954837761502_AdministratorAccess")
    python_cmd = prompt_with_default("pythonCmd", r".\.venv\Scripts\python.exe")
    deploy_role_name = prompt_with_default("deployRoleName", "PulumiDeploy")
    org = prompt_required("org", "jub-jub-bird-org")

    written: list[str] = []
    skipped: list[str] = []

    # Pulumi.yaml (project)
    pulumi_yaml_path = root / "Pulumi.yaml"
    pulumi_yaml_content = build_pulumi_project_yaml(project_name=slug)
    if write_text(pulumi_yaml_path, pulumi_yaml_content, force=args.force):
        written.append(pulumi_yaml_path.name)
    else:
        skipped.append(pulumi_yaml_path.name)

    # -----------------------
    # Network stack file
    # -----------------------
    network_account_id = prompt_required("Network accountId", "718311990857")
    hosted_zone_name = base_domain
    hosted_zone_id = prompt_required("hostedZoneId", "Z07653062FAMACMF1IY56")
    # Hard defaults for first deploy (can be edited later in YAML)
    adopt_existing_records = "false"
    protect_dns_records = "false"

    network_values = {
        "aws:profile": profile,
        "aws:region": region,
        f"{prefix}:accountId": _yaml_quote(network_account_id),
        f"{prefix}:adoptExistingRecords": _yaml_quote(adopt_existing_records),
        f"{prefix}:baseDomain": base_domain,
        f"{prefix}:deployRoleName": deploy_role_name,
        f"{prefix}:domainSlug": slug,
        f"{prefix}:hostedZoneId": hosted_zone_id,
        f"{prefix}:hostedZoneName": hosted_zone_name,
        f"{prefix}:org": org,
        f"{prefix}:protectDnsRecords": _yaml_quote(protect_dns_records),
        f"{prefix}:pythonCmd": python_cmd,
    }

    network_path = root / f"Pulumi.{slug}-network.yaml"
    if write_text(network_path, build_network_yaml(prefix, network_values), force=args.force):
        written.append(network_path.name)
    else:
        skipped.append(network_path.name)

    # -----------------------
    # Staging stack file (no secrets)
    # -----------------------
    staging_account_id = prompt_required("Staging accountId", "898147177165")
    staging_values = {
        "aws-native:profile": profile,
        "aws-native:region": region,
        "aws:profile": profile,
        "aws:region": region,
        f"{prefix}:accountId": _yaml_quote(staging_account_id),
        f"{prefix}:authApiCustomDomain": f"auth-api.staging.{base_domain}",
        f"{prefix}:baseDomain": base_domain,
        f"{prefix}:cognitoAuthDomain": f"auth.staging.{base_domain}",
        f"{prefix}:defaultRootObject": "index.html",
        f"{prefix}:deployRoleName": deploy_role_name,
        f"{prefix}:domainSlug": slug,
        f"{prefix}:enableApiLogging": _yaml_quote("true"),
        f"{prefix}:enableAuthApiDomain": _yaml_quote("false"),
        f"{prefix}:enableCognitoDomain": _yaml_quote("false"),
        f"{prefix}:enableCustomDomain": _yaml_quote("false"),
        f"{prefix}:logRetentionDays": _yaml_quote("7"),
        f"{prefix}:org": org,
        f"{prefix}:pythonCmd": python_cmd,
        f"{prefix}:redirectPath": "/auth/callback",
    }

    staging_path = root / f"Pulumi.{slug}-staging.yaml"
    if write_text(staging_path, build_workload_yaml_no_secrets(prefix, staging_values, "staging"), force=args.force):
        written.append(staging_path.name)
    else:
        skipped.append(staging_path.name)

    # -----------------------
    # Prod stack file (no secrets)
    # -----------------------
    prod_account_id = prompt_required("Prod accountId", "928100078384")
    prod_values = {
        "aws-native:profile": profile,
        "aws-native:region": region,
        "aws:profile": profile,
        "aws:region": region,
        f"{prefix}:accountId": _yaml_quote(prod_account_id),
        f"{prefix}:authApiCustomDomain": f"auth-api.{base_domain}",
        f"{prefix}:baseDomain": base_domain,
        f"{prefix}:cognitoAuthDomain": f"auth.{base_domain}",
        f"{prefix}:defaultRootObject": "index.html",
        f"{prefix}:deployRoleName": deploy_role_name,
        f"{prefix}:domainSlug": slug,
        f"{prefix}:enableApiLogging": _yaml_quote("true"),
        f"{prefix}:enableAuthApiDomain": _yaml_quote("false"),
        f"{prefix}:enableCognitoDomain": _yaml_quote("false"),
        f"{prefix}:enableCustomDomain": _yaml_quote("false"),
        f"{prefix}:logRetentionDays": _yaml_quote("7"),
        f"{prefix}:org": org,
        f"{prefix}:pythonCmd": python_cmd,
        f"{prefix}:redirectPath": "/auth/callback",
    }

    prod_path = root / f"Pulumi.{slug}-prod.yaml"
    if write_text(prod_path, build_workload_yaml_no_secrets(prefix, prod_values, "prod"), force=args.force):
        written.append(prod_path.name)
    else:
        skipped.append(prod_path.name)

    print("\n=== Phase 1 Summary ===")
    if written:
        print("Written/Updated:")
        for n in written:
            print(f"  - {n}")
    if skipped:
        print("Skipped (use --force to overwrite):")
        for n in skipped:
            print(f"  - {n}")

    # Phase 2: secrets injection (staging+prod by default)
    if args.inject_secrets:
        envs = [e.strip() for e in args.inject_envs.split(",") if e.strip()]
        print("\n=== Phase 2 (inject secrets) ===")
        for env in envs:
            if env not in ("staging", "prod"):
                raise ValueError(f"Unsupported env for injection: {env}")
            pulumi_inject_secrets_for_env(
                repo_root=root,
                base_domain=base_domain,
                slug=slug,
                env=env,
                region=region,
                profile=profile,
            )
    else:
        print("\n(Phase 2 skipped) Re-run with --inject-secrets to write secure: secrets into the stack YAMLs.")

    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
