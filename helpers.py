import base64
import pulumi
import re

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def workload_aliases(env: str, base_domain: str) -> list[str]:
    """
    Derive aliases from a single base domain.

    prod:
      - example.com
      - www.example.com

    staging:
      - staging.example.com
      - www.staging.example.com
    """
    base_domain = (base_domain or "").strip().lower().rstrip(".")
    if not base_domain:
        raise Exception("Missing base domain. Set config key: website-s3-cf-cognito-lambda:baseDomain")

    if env == "prod":
        return [base_domain, f"www.{base_domain}"]

    if env == "staging":
        return [f"staging.{base_domain}", f"www.staging.{base_domain}"]

    return []


def _slug(s: str) -> str:
    s = (s or "").strip().lower().rstrip(".")
    s = re.sub(r"[^a-z0-9-]", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s[:200]


def _r53_import_id(zone_id: str, record_name: str, record_type: str) -> str:
    return f"{zone_id}_{record_name.rstrip('.')}_{record_type.upper()}"


def pem_from_config_plain(cfg: pulumi.Config, name: str, name_b64: str) -> str:
    raw = cfg.get(name)
    b64 = cfg.get(name_b64)
    if raw:
        return raw
    if not b64:
        raise Exception(f"Missing config {name} or {name_b64}")
    return base64.b64decode(b64.encode()).decode()
