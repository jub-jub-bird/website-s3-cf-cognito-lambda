import pulumi
import pulumi_aws as aws

from apigw_account_logging import (
    create_apigw_access_log_group,
    create_apigw_execution_log_group,
)


def create_auth_apigw(
    *,
    cfg: pulumi.Config,
    stack: str,
    domain_slug: str,
    callback_region: str,
    enable_api_logging: bool,
    enable_auth_api_domain: bool,
    auth_api_custom_domain: str | None,
    ACCESS_LOG_FORMAT: str,
    log_retention_days: int,
    apigw_account: aws.apigateway.Account | None,
    login_lambda: aws.lambda_.Function,
    callback_lambda: aws.lambda_.Function,
    logout_lambda: aws.lambda_.Function,
    callback_provider: aws.Provider,
):
    """
    Creates the Auth API Gateway:
      - /auth/login    -> login_lambda
      - /auth/callback -> callback_lambda
      - /auth/logout   -> logout_lambda
    Also creates stage + logging, optional custom domain (regional),
    and returns the origin domain/path CloudFront should use.

    Returns:
      (api, stage_api, auth_origin_domain_for_cf, auth_origin_path_for_cf)
    """

    api = aws.apigateway.RestApi(
        "authApi",
        name=f"{domain_slug}-{stack}-auth-api",
        disable_execute_api_endpoint=True,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    auth_res = aws.apigateway.Resource(
        "authApiAuthRes",
        rest_api=api.id,
        parent_id=api.root_resource_id,
        path_part="auth",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    cb_res = aws.apigateway.Resource(
        "authApiCallbackRes",
        rest_api=api.id,
        parent_id=auth_res.id,
        path_part="callback",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    login_res = aws.apigateway.Resource(
        "authApiLoginRes",
        rest_api=api.id,
        parent_id=auth_res.id,
        path_part="login",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    logout_res = aws.apigateway.Resource(
        "authApiLogoutRes",
        rest_api=api.id,
        parent_id=auth_res.id,
        path_part="logout",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    # Methods
    login_method = aws.apigateway.Method(
        "authApiLoginMethod",
        rest_api=api.id,
        resource_id=login_res.id,
        http_method="GET",
        authorization="NONE",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    cb_method = aws.apigateway.Method(
        "authApiCallbackMethod",
        rest_api=api.id,
        resource_id=cb_res.id,
        http_method="GET",
        authorization="NONE",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    logout_method = aws.apigateway.Method(
        "authApiLogoutMethod",
        rest_api=api.id,
        resource_id=logout_res.id,
        http_method="GET",
        authorization="NONE",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    # Integrations (AWS_PROXY)
    login_integ = aws.apigateway.Integration(
        "authApiLoginIntegration",
        rest_api=api.id,
        resource_id=login_res.id,
        http_method="GET",
        integration_http_method="POST",
        type="AWS_PROXY",
        uri=login_lambda.invoke_arn,
        opts=pulumi.ResourceOptions(
            provider=callback_provider,
            depends_on=[login_method],
        ),
    )

    cb_integ = aws.apigateway.Integration(
        "authApiCallbackIntegration",
        rest_api=api.id,
        resource_id=cb_res.id,
        http_method="GET",
        integration_http_method="POST",
        type="AWS_PROXY",
        uri=callback_lambda.invoke_arn,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    logout_integ = aws.apigateway.Integration(
        "authApiLogoutIntegration",
        rest_api=api.id,
        resource_id=logout_res.id,
        http_method="GET",
        integration_http_method="POST",
        type="AWS_PROXY",
        uri=logout_lambda.invoke_arn,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    # Permissions
    aws.lambda_.Permission(
        "authApiInvokePermission",
        action="lambda:InvokeFunction",
        function=callback_lambda.name,
        principal="apigateway.amazonaws.com",
        source_arn=pulumi.Output.concat(api.execution_arn, "/*/*"),
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    aws.lambda_.Permission(
        "authApiLoginInvokePermission",
        action="lambda:InvokeFunction",
        function=login_lambda.name,
        principal="apigateway.amazonaws.com",
        source_arn=pulumi.Output.concat(api.execution_arn, "/*/*"),
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    aws.lambda_.Permission(
        "authApiLogoutInvokePermission",
        action="lambda:InvokeFunction",
        function=logout_lambda.name,
        principal="apigateway.amazonaws.com",
        source_arn=pulumi.Output.concat(api.execution_arn, "/*/*"),
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    deployment = aws.apigateway.Deployment(
        "authApiDeploymentv2",
        rest_api=api.id,
        triggers={
            "redeploy": pulumi.Output.concat(
                callback_lambda.urn, "|",
                logout_lambda.urn, "|",
                login_lambda.urn,
            )
        },
        opts=pulumi.ResourceOptions(
            provider=callback_provider,
            depends_on=[cb_integ, logout_integ, login_integ],
        ),
    )

    stage_name = cfg.get("authApiStageName") or "v1"

    # -------------------------------------------------------------------
    # Logging: create log groups via your helper file (deterministic names)
    # -------------------------------------------------------------------
    apigw_access_log_group = create_apigw_access_log_group(
        stack=stack,
        domain_slug=domain_slug,
        log_retention_days=log_retention_days,
        callback_provider=callback_provider,
    )

    # Create execution log group with API's fixed naming convention.
    # NOTE: No adopt/import. If it already exists, this will fail.
    # If this continues to bite you, the fix is to *not* manage execution log groups.
    _apigw_execution_log_group = create_apigw_execution_log_group(
        stack=stack,
        rest_api_id=api.id,
        stage_name=stage_name,
        log_retention_days=log_retention_days,
        callback_provider=callback_provider,
    )

    stage_api = aws.apigateway.Stage(
        "authApiStage",
        rest_api=api.id,
        deployment=deployment.id,
        stage_name=stage_name,
        access_log_settings=aws.apigateway.StageAccessLogSettingsArgs(
            destination_arn=apigw_access_log_group.arn,
            format=ACCESS_LOG_FORMAT,
        ) if (enable_api_logging and apigw_access_log_group is not None) else None,
        opts=pulumi.ResourceOptions(
            provider=callback_provider,
            depends_on=[deployment] + ([apigw_account] if (enable_api_logging and apigw_account is not None) else []),
        ),
    )

    if enable_api_logging:
        aws.apigateway.MethodSettings(
            "authApiMethodSettings",
            rest_api=api.id,
            stage_name=stage_api.stage_name,
            method_path="*/*",
            settings=aws.apigateway.MethodSettingsSettingsArgs(
                metrics_enabled=True,
                logging_level="INFO",
                data_trace_enabled=False,
            ),
            opts=pulumi.ResourceOptions(
                provider=callback_provider,
                depends_on=[apigw_account] if apigw_account is not None else None,
            ),
        )

    # -------------------------------------------------------------------
    # Optional: API Gateway Custom Domain (REGIONAL)
    # -------------------------------------------------------------------
    api_custom_domain = None
    auth_api_regional_cert = None

    auth_origin_domain_for_cf = None
    auth_origin_path_for_cf = None

    if auth_api_custom_domain:
        auth_api_regional_cert = aws.acm.Certificate(
            "authApiRegionalCert",
            domain_name=auth_api_custom_domain,
            validation_method="DNS",
            opts=pulumi.ResourceOptions(provider=callback_provider),
        )
        pulumi.export("authApiRegionalCertArn", auth_api_regional_cert.arn)

        auth_api_regional_cert_validation_records = auth_api_regional_cert.domain_validation_options.apply(
            lambda opts: [
                {"name": o.resource_record_name, "type": o.resource_record_type, "value": o.resource_record_value}
                for o in (opts or [])
            ]
        )
        pulumi.export("authApiRegionalCertValidationRecords", auth_api_regional_cert_validation_records)

        if enable_auth_api_domain:
            api_custom_domain = aws.apigateway.DomainName(
                "authApiDomainName",
                domain_name=auth_api_custom_domain,
                regional_certificate_arn=auth_api_regional_cert.arn,
                endpoint_configuration={"types": "REGIONAL"},
                security_policy="TLS_1_2",
                opts=pulumi.ResourceOptions(provider=callback_provider),
            )

            pulumi.export("authApiRegionalDomainName", api_custom_domain.domain_name)
            pulumi.export("authApiRegionalTargetDomainName", api_custom_domain.regional_domain_name)
            pulumi.export("authApiRegionalHostedZoneId", api_custom_domain.regional_zone_id)

            aws.apigateway.BasePathMapping(
                "authApiBasePathMapping",
                rest_api=api.id,
                stage_name=stage_api.stage_name,
                domain_name=api_custom_domain.domain_name,
                opts=pulumi.ResourceOptions(provider=callback_provider),
            )

            auth_origin_domain_for_cf = api_custom_domain.domain_name
            auth_origin_path_for_cf = ""
        else:
            auth_origin_domain_for_cf = pulumi.Output.concat(api.id, ".execute-api.", callback_region, ".amazonaws.com")
            auth_origin_path_for_cf = f"/{stage_name}"
    else:
        auth_origin_domain_for_cf = pulumi.Output.concat(api.id, ".execute-api.", callback_region, ".amazonaws.com")
        auth_origin_path_for_cf = f"/{stage_name}"

    pulumi.export("authOriginDomainUsedByCloudFront", auth_origin_domain_for_cf)
    pulumi.export("authOriginPathUsedByCloudFront", auth_origin_path_for_cf)

    auth_api_invoke_url = pulumi.Output.concat(
        "https://",
        api.id,
        ".execute-api.",
        callback_region,
        ".amazonaws.com/",
        stage_name,
        "/auth/callback",
    )
    pulumi.export("authApiInvokeUrl", auth_api_invoke_url)
    pulumi.export("enableApiLogging", enable_api_logging)

    return api, stage_api, auth_origin_domain_for_cf, auth_origin_path_for_cf
