import re
import base64
import pulumi
import pulumi_aws as aws
import pulumi_aws_native as aws_native
from pathlib import Path
import json

from helpers import workload_aliases, _slug, _r53_import_id, pem_from_config_plain
from assets import ACCESS_LOG_FORMAT, bg_svg_b64
from providers import make_providers
from apigw_account_logging import setup_apigw_account_logging
from workload_prod_staging import deploy_workload_prod_staging
from network_dns import deploy_network_dns

cfg = pulumi.Config()

# -------------------------------------------------------------------
# Core config (required in every stack)
# -------------------------------------------------------------------
account_id = cfg.require("accountId")
role_name = cfg.require("deployRoleName")
domain_slug = cfg.require("domainSlug")
origin_verify_secret = cfg.get_secret("originVerifySecret")

# Network/DNS config (required only for network stack)
hosted_zone_id = cfg.get("hostedZoneId")
hosted_zone_name = cfg.get("hostedZoneName")

# Optional knobs
default_root_object = cfg.get("defaultRootObject") or "index.html"
org = cfg.get("org") or "jub-jub-bird-org"
project = pulumi.get_project()
base_domain = cfg.require("baseDomain")

# Phase gates
enable_custom_domain = cfg.get_bool("enableCustomDomain") or False
enable_cognito_domain = cfg.get_bool("enableCognitoDomain") or False
adopt_existing_records = cfg.get_bool("adoptExistingRecords") or False
enable_auth_api_domain = cfg.get_bool("enableAuthApiDomain") or False
enable_api_logging = cfg.get_bool("enableApiLogging") or False

log_retention_days = int(cfg.get("logRetentionDays") or "7")
pulumi.export("logRetentionDays", log_retention_days)

# Optional API Gateway custom domain
auth_api_custom_domain = cfg.get("authApiCustomDomain")

full_stack = pulumi.get_stack()
stack = full_stack.split("-")[-1]
iac = aws.get_caller_identity()
pulumi.export("stack", stack)

callback_region = cfg.get("callbackRegion") or "eu-west-2"

target_provider, native_target_provider, use1_provider, callback_provider = make_providers(
    account_id=account_id,
    role_name=role_name,
    callback_region=callback_region,
    target_region="eu-west-2",
)

apigw_account = setup_apigw_account_logging(
    stack=stack,
    domain_slug=domain_slug,
    callback_provider=callback_provider,
)

deploy_workload_prod_staging(
    cfg=cfg,
    stack=stack,
    domain_slug=domain_slug,
    default_root_object=default_root_object,
    enable_custom_domain=enable_custom_domain,
    enable_cognito_domain=enable_cognito_domain,
    enable_auth_api_domain=enable_auth_api_domain,
    enable_api_logging=enable_api_logging,
    log_retention_days=log_retention_days,
    auth_api_custom_domain=auth_api_custom_domain,
    origin_verify_secret=origin_verify_secret,
    target_provider=target_provider,
    native_target_provider=native_target_provider,
    use1_provider=use1_provider,
    callback_provider=callback_provider,
    callback_region=callback_region,
    ACCESS_LOG_FORMAT=ACCESS_LOG_FORMAT,
    bg_svg_b64=bg_svg_b64,
    apigw_account=apigw_account,
    workload_aliases=workload_aliases,
    base_domain=base_domain,              # <-- ADD THIS
    pem_from_config_plain=pem_from_config_plain,
)


deploy_network_dns(
    cfg=cfg,
    org=org,
    project=project,
    stack=stack,
    hosted_zone_id=hosted_zone_id,
    hosted_zone_name=hosted_zone_name,
    adopt_existing_records=adopt_existing_records,
    target_provider=target_provider,
)
