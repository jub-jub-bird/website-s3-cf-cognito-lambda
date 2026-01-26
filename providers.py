import pulumi
import pulumi_aws as aws
import pulumi_aws_native as aws_native


def make_providers(
    *,
    account_id: str,
    role_name: str,
    callback_region: str,
    target_region: str = "eu-west-2",
):
    """
    Create AWS providers used by this project.

    - target_provider: main workload provider (target_region)
    - native_target_provider: aws-native provider (target_region)
    - use1_provider: us-east-1 (ACM for CloudFront / Cognito domains)
    - callback_provider: region hosting the auth callback API (callback_region)
    """
    target_provider = aws.Provider(
        "target",
        assume_roles=[{
            "roleArn": f"arn:aws:iam::{account_id}:role/{role_name}",
            "sessionName": "pulumi",
        }],
        region=target_region,
    )

    native_target_provider = aws_native.Provider(
        "nativeTarget",
        region=target_region,
        assume_role=aws_native.ProviderAssumeRoleArgs(
            role_arn=f"arn:aws:iam::{account_id}:role/{role_name}",
            session_name="pulumi",
        ),
    )

    use1_provider = aws.Provider(
        "use1",
        region="us-east-1",
        assume_roles=[{
            "roleArn": f"arn:aws:iam::{account_id}:role/{role_name}",
            "sessionName": "pulumi",
        }],
    )

    callback_provider = aws.Provider(
        "callback",
        region=callback_region,
        assume_roles=[{
            "roleArn": f"arn:aws:iam::{account_id}:role/{role_name}",
            "sessionName": "pulumi",
        }],
    )

    return target_provider, native_target_provider, use1_provider, callback_provider
