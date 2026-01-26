import pulumi
import pulumi_aws as aws
import pulumi_aws_native as aws_native

from workload_certs import create_workload_certs
from workload_cognito import create_workload_cognito
from workload_lambdas import create_auth_lambdas
from workload_apigw_auth import create_auth_apigw
from workload_cloudfront import create_cloudfront_distribution
from workload_s3_site import create_site_bucket_and_oac, attach_cloudfront_read_policy


def build_auth_gate_function_code(*, fallback_host: str, post_login_path: str) -> pulumi.Output[str]:
    """
    CloudFront Function code for the auth gate.

    - Only acts on / and /index.html
    - If signed-cookie trio exists, redirects to post_login_path
    - Otherwise redirects to /auth/login?host=<host>
    """
    return pulumi.Output.concat(
        "function handler(event) {\n",
        "  var request = event.request;\n",
        "  var uri = request.uri || \"/\";\n",
        "  var headers = request.headers || {};\n",
        "  var host = (headers.host && headers.host.value) ? headers.host.value : \"\";\n",
        f"  var fallbackHost = \"{fallback_host}\";\n",
        "  if (!host) host = fallbackHost;\n",
        "\n",
        "  // Only act on the homepage\n",
        "  if (!(uri === \"/\" || uri === \"/index.html\")) {\n",
        "    return request;\n",
        "  }\n",
        "\n",
        "  var cookieHeader = headers.cookie ? headers.cookie.value : \"\";\n",
        "  var hasPolicy = cookieHeader.indexOf(\"CloudFront-Policy=\") !== -1;\n",
        "  var hasSig = cookieHeader.indexOf(\"CloudFront-Signature=\") !== -1;\n",
        "  var hasKey = cookieHeader.indexOf(\"CloudFront-Key-Pair-Id=\") !== -1;\n",
        "\n",
        "  // Logged in → send to protected start page\n",
        "  if (hasPolicy && hasSig && hasKey) {\n",
        "    return {\n",
        "      statusCode: 302,\n",
        "      statusDescription: \"Found\",\n",
        "      headers: {\n",
        f"        \"location\": {{ \"value\": \"https://\" + host + \"{post_login_path}\" }},\n",
        "        \"cache-control\": { \"value\": \"no-store\" }\n",
        "      }\n",
        "    };\n",
        "  }\n",
        "\n",
        "  // Not logged in → route via /auth/login (state signing happens there)\n",
        "  var location = \"https://\" + host + \"/auth/login?host=\" + encodeURIComponent(host);\n",
        "\n",
        "  return {\n",
        "    statusCode: 302,\n",
        "    statusDescription: \"Found\",\n",
        "    headers: {\n",
        "      \"location\": { \"value\": location },\n",
        "      \"cache-control\": { \"value\": \"no-store\" }\n",
        "    }\n",
        "  };\n",
        "}\n",
    )


def deploy_workload_prod_staging(
    *,
    cfg: pulumi.Config,
    stack: str,
    domain_slug: str,
    default_root_object: str,
    enable_custom_domain: bool,
    enable_cognito_domain: bool,
    enable_auth_api_domain: bool,
    enable_api_logging: bool,
    log_retention_days: int,
    auth_api_custom_domain: str | None,
    origin_verify_secret,
    # providers
    target_provider: aws.Provider,
    native_target_provider: aws_native.Provider,
    use1_provider: aws.Provider,
    callback_provider: aws.Provider,
    callback_region: str,
    # shared objects
    ACCESS_LOG_FORMAT: str,
    bg_svg_b64: str,
    apigw_account: aws.apigateway.Account | None,
    # helpers
    workload_aliases,
    base_domain: str,              # <-- ADD THIS
    pem_from_config_plain,
):
    """
    Deploy prod/staging workload resources.

    Mostly orchestrates module calls; keeps CloudFront auth-gate resources here
    because they are frequently iterated and tightly coupled to config.
    """
    if stack not in ("prod", "staging"):
        return

    aliases = workload_aliases(stack, base_domain)
    if len(aliases) != 2:
        raise Exception("Expected exactly 2 aliases per workload stack.")
    allowed_hosts_csv = ",".join(aliases)

    # -------------------------------------------------------------------
    # PEMs for signed cookies
    # -------------------------------------------------------------------
    public_key_pem = pem_from_config_plain(cfg, "cloudfrontPublicKeyPem", "cloudfrontPublicKeyPemB64")

    cloudfront_private_key_pem = cfg.get_secret("cloudfrontPrivateKeyPem")
    if cloudfront_private_key_pem is None:
        cloudfront_private_key_pem_b64 = cfg.get_secret("cloudfrontPrivateKeyPemB64")
        if cloudfront_private_key_pem_b64 is None:
            raise Exception("Missing secret: cloudfrontPrivateKeyPem or cloudfrontPrivateKeyPemB64")
        cloudfront_private_key_pem = cloudfront_private_key_pem_b64.apply(
            lambda s: __import__("base64").b64decode(s.encode("utf-8")).decode("utf-8")
        )

    cognito_auth_domain = cfg.require("cognitoAuthDomain")
    redirect_path = cfg.get("redirectPath") or "/auth/callback"
    cookie_domain_base = cfg.get("cookieDomainBase")
    post_login_path = cfg.get("postLoginPath") or "/private/start.html"

    # CloudFront Function should only ever redirect to a path (no scheme/host)
    post_login_path_cf = post_login_path.strip() if post_login_path else "/private/start.html"
    if not post_login_path_cf.startswith("/"):
        post_login_path_cf = "/" + post_login_path_cf

    # Treat origin verify secret consistently as secret output
    origin_verify_secret_out = pulumi.Output.secret(origin_verify_secret)

    safe_replace_opts = pulumi.ResourceOptions(
        provider=target_provider,
        delete_before_replace=False,
    )

    # -------------------------------------------------------------------
    # CloudFront Public Key + Key Group (signed cookies)
    # -------------------------------------------------------------------
    cf_public_key = aws.cloudfront.PublicKey(
        "cfPublicKey",
        comment=f"{domain_slug} {stack} public key for signed cookies",
        encoded_key=public_key_pem,
        opts=safe_replace_opts,
    )

    cloudfront_key_pair_id = cf_public_key.id

    cf_key_group = aws.cloudfront.KeyGroup(
        "cfKeyGroup",
        comment=f"{domain_slug} {stack} key group for signed cookies",
        items=[cf_public_key.id],
        opts=safe_replace_opts,
    )

    pulumi.export("cloudFrontPublicKeyId", cf_public_key.id)
    pulumi.export("cloudFrontKeyGroupId", cf_key_group.id)

    # -------------------------------------------------------------------
    # Certificates (us-east-1)
    # -------------------------------------------------------------------
    site_cert, _site_cert_validation, auth_cert, auth_cert_validation = create_workload_certs(
        stack=stack,
        domain_slug=domain_slug,
        aliases=aliases,
        cognito_auth_domain=cognito_auth_domain,
        enable_custom_domain=enable_custom_domain,
        enable_cognito_domain=enable_cognito_domain,
        use1_provider=use1_provider,
    )

    # -------------------------------------------------------------------
    # Cognito (User Pool / Client / Optional custom domain)
    # -------------------------------------------------------------------
    _user_pool, user_pool_client, _user_pool_domain = create_workload_cognito(
        stack=stack,
        domain_slug=domain_slug,
        aliases=aliases,
        cognito_auth_domain=cognito_auth_domain,
        redirect_path=redirect_path,
        enable_cognito_domain=enable_cognito_domain,
        bg_svg_b64=bg_svg_b64,
        target_provider=target_provider,
        native_target_provider=native_target_provider,
        use1_provider=use1_provider,
        auth_cert=auth_cert,
        auth_cert_validation=auth_cert_validation,
    )

    # -------------------------------------------------------------------
    # Auth lambdas (login/callback/logout) + log groups
    # -------------------------------------------------------------------
    _lambda_role, login_lambda, callback_lambda, logout_lambda, _cookie_ttl_seconds = create_auth_lambdas(
        cfg=cfg,
        aliases=aliases,
        domain_slug=domain_slug,
        stack=stack,
        allowed_hosts_csv=allowed_hosts_csv,
        cognito_auth_domain=cognito_auth_domain,
        redirect_path=redirect_path,
        post_login_path=post_login_path,
        cookie_domain_base=cookie_domain_base,
        user_pool_client=user_pool_client,
        cloudfront_key_pair_id=cloudfront_key_pair_id,
        cloudfront_private_key_pem=cloudfront_private_key_pem,
        origin_verify_secret=origin_verify_secret_out,
        callback_provider=callback_provider,
        log_retention_days=log_retention_days,
    )

    # -------------------------------------------------------------------
    # API Gateway for /auth/* + optional regional custom domain
    # (returns values CloudFront needs for the auth origin)
    # -------------------------------------------------------------------
    _api, _stage_api, auth_origin_domain_for_cf, auth_origin_path_for_cf = create_auth_apigw(
        cfg=cfg,
        stack=stack,
        domain_slug=domain_slug,
        callback_region=callback_region,
        enable_api_logging=enable_api_logging,
        enable_auth_api_domain=enable_auth_api_domain,
        auth_api_custom_domain=auth_api_custom_domain,
        ACCESS_LOG_FORMAT=ACCESS_LOG_FORMAT,
        log_retention_days=log_retention_days,
        apigw_account=apigw_account,
        login_lambda=login_lambda,
        callback_lambda=callback_lambda,
        logout_lambda=logout_lambda,
        callback_provider=callback_provider,
    )

    # -------------------------------------------------------------------
    # CloudFront managed policies (lookup by name)
    # -------------------------------------------------------------------
    caching_disabled = aws.cloudfront.get_cache_policy(
        name="Managed-CachingDisabled",
        opts=pulumi.InvokeOptions(provider=target_provider),
    )

    all_viewer_except_host = aws.cloudfront.get_origin_request_policy(
        name="Managed-AllViewerExceptHostHeader",
        opts=pulumi.InvokeOptions(provider=target_provider),
    )

    # -------------------------------------------------------------------
    # Viewer cert for the distribution
    # -------------------------------------------------------------------
    viewer_cert = (
        aws.cloudfront.DistributionViewerCertificateArgs(cloudfront_default_certificate=True)
        if not enable_custom_domain
        else aws.cloudfront.DistributionViewerCertificateArgs(
            acm_certificate_arn=site_cert.arn,
            ssl_support_method="sni-only",
            minimum_protocol_version="TLSv1.2_2021",
        )
    )

    # -------------------------------------------------------------------
    # CloudFront Response Headers Policy (security headers)
    # -------------------------------------------------------------------
    security_headers_policy = aws.cloudfront.ResponseHeadersPolicy(
        "securityHeadersPolicy",
        name=f"{domain_slug}-{stack}-security-headers",
        comment="Baseline security headers (no CSP yet)",
        security_headers_config=aws.cloudfront.ResponseHeadersPolicySecurityHeadersConfigArgs(
            strict_transport_security=aws.cloudfront.ResponseHeadersPolicySecurityHeadersConfigStrictTransportSecurityArgs(
                access_control_max_age_sec=31536000,
                include_subdomains=True,
                preload=False,
                override=True,
            ),
            content_type_options=aws.cloudfront.ResponseHeadersPolicySecurityHeadersConfigContentTypeOptionsArgs(
                override=True,
            ),
            frame_options=aws.cloudfront.ResponseHeadersPolicySecurityHeadersConfigFrameOptionsArgs(
                frame_option="DENY",
                override=True,
            ),
            referrer_policy=aws.cloudfront.ResponseHeadersPolicySecurityHeadersConfigReferrerPolicyArgs(
                referrer_policy="strict-origin-when-cross-origin",
                override=True,
            ),
            xss_protection=aws.cloudfront.ResponseHeadersPolicySecurityHeadersConfigXssProtectionArgs(
                protection=True,
                mode_block=True,
                override=True,
            ),
            content_security_policy=aws.cloudfront.ResponseHeadersPolicySecurityHeadersConfigContentSecurityPolicyArgs(
                content_security_policy=(
                    "default-src 'self'; "
                    "base-uri 'self'; "
                    "object-src 'none'; "
                    "frame-ancestors 'none'; "
                    "img-src 'self' data:; "
                    "style-src 'self' 'unsafe-inline'; "
                    "script-src 'self'"
                ),
                override=True,
            ),
        ),
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    # -------------------------------------------------------------------
    # CloudFront Function (auth gate)
    # -------------------------------------------------------------------
    function_code = build_auth_gate_function_code(
        fallback_host=aliases[0],
        post_login_path=post_login_path_cf,
    )

    cf_function = aws.cloudfront.Function(
        "authGate",
        name=f"{domain_slug}-{stack}-auth-gate",
        runtime="cloudfront-js-1.0",
        comment=f"{domain_slug} {stack} auth gate for /private/*",
        code=function_code,
        publish=True,
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    pulumi.export("cloudFrontFunctionName", cf_function.name)

    # -------------------------------------------------------------------
    # S3 site bucket + OAC
    # -------------------------------------------------------------------
    site = create_site_bucket_and_oac(
        stack=stack,
        domain_slug=domain_slug,
        target_provider=target_provider,
    )

    site_bucket = site["site_bucket"]
    oac = site["oac"]

    # -------------------------------------------------------------------
    # CloudFront distribution
    # -------------------------------------------------------------------
    cf_behavior = {
        "viewer_cert": viewer_cert,
        "security_headers_policy": security_headers_policy,
        "cf_function": cf_function,
        "cf_key_group": cf_key_group,
        "caching_disabled": caching_disabled,
        "all_viewer_except_host": all_viewer_except_host,
    }

    dist = create_cloudfront_distribution(
        stack=stack,
        domain_slug=domain_slug,
        default_root_object=default_root_object,
        enable_custom_domain=enable_custom_domain,
        aliases=aliases,
        site_origin={
            "site_bucket": site_bucket,
            "oac": oac,
        },
        auth_origin={
            "domain_name": auth_origin_domain_for_cf,
            "origin_path": auth_origin_path_for_cf,
            "origin_verify_secret": origin_verify_secret_out,
        },
        behavior=cf_behavior,
        target_provider=target_provider,
    )

    attach_cloudfront_read_policy(
        site_bucket=site_bucket,
        dist=dist,
        target_provider=target_provider,
    )

    pulumi.export("customDomainEnabled", enable_custom_domain)
    pulumi.export("aliases", aliases)
