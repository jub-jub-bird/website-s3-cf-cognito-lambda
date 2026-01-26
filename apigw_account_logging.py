# apigw_account_logging.py
import pulumi
import pulumi_aws as aws


def setup_apigw_account_logging(
    *,
    stack: str,
    domain_slug: str,
    callback_provider: aws.Provider,
) -> aws.apigateway.Account | None:
    """
    Sets up API Gateway account-level logging role + Account resource, per region.

    Notes:
    - This is an ACCOUNT-LEVEL setting in the target region (callback_provider region).
    - Only creates for prod/staging.
    """
    if stack not in ("prod", "staging"):
        return None

    # Make the role name deterministic (and env-specific)
    apigw_logs_role_name = f"{domain_slug}-{stack}-apigw-logs"

    apigw_logs_role = aws.iam.Role(
        "apigwLogsRole",
        name=apigw_logs_role_name,
        assume_role_policy=aws.iam.get_policy_document_output(
            statements=[
                aws.iam.GetPolicyDocumentStatementArgs(
                    actions=["sts:AssumeRole"],
                    principals=[
                        aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                            type="Service",
                            identifiers=["apigateway.amazonaws.com"],
                        )
                    ],
                )
            ]
        ).json,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    aws.iam.RolePolicyAttachment(
        "apigwLogsRoleAttach",
        role=apigw_logs_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    # Account-level setting (one per AWS account per region)
    apigw_account = aws.apigateway.Account(
        "apigwAccount",
        cloudwatch_role_arn=apigw_logs_role.arn,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    return apigw_account


def create_apigw_access_log_group(
    *,
    stack: str,
    domain_slug: str,
    log_retention_days: int,
    callback_provider: aws.Provider,
) -> aws.cloudwatch.LogGroup | None:
    """
    Creates a deterministic CloudWatch LogGroup for API Gateway *access logs*.

    This is the log group you wire into apigateway.Stage.access_log_settings.destination_arn.

    We do NOT import/adopt. If the log group already exists, this will fail.
    """
    if stack not in ("prod", "staging"):
        return None

    lg_name = f"/aws/apigateway/{domain_slug}-{stack}-auth-access"

    return aws.cloudwatch.LogGroup(
        "authApiAccessLogs",
        name=lg_name,
        retention_in_days=log_retention_days,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )


def create_apigw_execution_log_group(
    *,
    stack: str,
    rest_api_id: pulumi.Input[str],
    stage_name: pulumi.Input[str],
    log_retention_days: int,
    callback_provider: aws.Provider,
) -> aws.cloudwatch.LogGroup | None:
    """
    Creates the CloudWatch LogGroup for API Gateway *execution logs*.

    IMPORTANT:
    - API Gateway uses a fixed naming convention:
        API-Gateway-Execution-Logs_<restApiId>/<stageName>
    - We do NOT import/adopt. If it already exists, this will fail.
    """
    if stack not in ("prod", "staging"):
        return None

    lg_name = pulumi.Output.concat(
        "API-Gateway-Execution-Logs_",
        rest_api_id,
        "/",
        stage_name,
    )

    return aws.cloudwatch.LogGroup(
        "authApiExecutionLogs",
        name=lg_name,
        retention_in_days=log_retention_days,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )
