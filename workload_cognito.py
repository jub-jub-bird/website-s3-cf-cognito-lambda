import pulumi
import pulumi_aws as aws
import pulumi_aws_native as aws_native


def create_workload_cognito(
    *,
    stack: str,
    domain_slug: str,
    aliases: list[str],
    cognito_auth_domain: str,
    redirect_path: str,
    enable_cognito_domain: bool,
    bg_svg_b64: str,
    target_provider: aws.Provider,
    native_target_provider: aws_native.Provider,
    use1_provider: aws.Provider,
    auth_cert: aws.acm.Certificate,
    auth_cert_validation: aws.acm.CertificateValidation | None,
):
    """
    Creates:
      - Cognito User Pool + Client
      - Managed Login Branding (aws-native)
      - Optional Cognito custom domain (with cert in us-east-1)

    Returns:
      (user_pool, user_pool_client, user_pool_domain_or_none)
    """

    # -------------------------------------------------------------------
    # Cognito User Pool + Client
    # -------------------------------------------------------------------
    callback_urls = [
        f"https://{aliases[0]}{redirect_path}",
        f"https://{aliases[1]}{redirect_path}",
    ]
    logout_urls = [
        f"https://{aliases[0]}/",
        f"https://{aliases[1]}/",
        f"https://{aliases[0]}/logged-out.html",
        f"https://{aliases[1]}/logged-out.html",
    ]

    user_pool = aws.cognito.UserPool(
        "userPool",
        name=f"{domain_slug}-{stack}-users",
        auto_verified_attributes=["email"],
        # disables self sign-up from the Hosted UI
        admin_create_user_config=aws.cognito.UserPoolAdminCreateUserConfigArgs(
            allow_admin_create_user_only=True,
        ),
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    user_pool_client = aws.cognito.UserPoolClient(
        "userPoolClient",
        name=f"{domain_slug}-{stack}-app",
        user_pool_id=user_pool.id,
        generate_secret=True,
        allowed_oauth_flows_user_pool_client=True,
        allowed_oauth_flows=["code"],
        allowed_oauth_scopes=["openid", "email", "profile"],
        supported_identity_providers=["COGNITO"],
        callback_urls=callback_urls,
        logout_urls=logout_urls,
        explicit_auth_flows=[
            "ALLOW_USER_SRP_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    managed_login_branding = aws_native.cognito.ManagedLoginBranding(
        "managedLoginBranding",
        user_pool_id=user_pool.id,
        client_id=user_pool_client.id,
        assets=[aws_native.cognito.ManagedLoginBrandingAssetTypeArgs(
            category="PAGE_BACKGROUND",
            color_mode="LIGHT",
            extension="SVG",
            bytes=bg_svg_b64,
        )],
        settings={
            "categories": {
                "global": {
                    "colorSchemeMode": "LIGHT",
                    "pageHeader": {"enabled": False},
                    "pageFooter": {"enabled": False},
                },
                "form": {
                    "displayGraphics": True,
                    "location": {"horizontal": "CENTER", "vertical": "CENTER"},
                },
            }
        },
        opts=pulumi.ResourceOptions(
            depends_on=[user_pool_client],
            provider=native_target_provider,
        ),
    )

    pulumi.export("cognitoUserPoolId", user_pool.id)
    pulumi.export("cognitoClientId", user_pool_client.id)
    pulumi.export("cognitoDomainName", cognito_auth_domain)
    pulumi.export("enableCognitoDomain", enable_cognito_domain)

    user_pool_domain = None
    if enable_cognito_domain:
        user_pool_domain = aws.cognito.UserPoolDomain(
            "userPoolDomain",
            domain=cognito_auth_domain,
            managed_login_version=2,
            user_pool_id=user_pool.id,
            certificate_arn=auth_cert.arn,
            opts=pulumi.ResourceOptions(
                provider=target_provider,
                depends_on=[auth_cert_validation] if auth_cert_validation else None,
            ),
        )
        pulumi.export("cognitoDomainCloudFront", user_pool_domain.cloudfront_distribution)
        pulumi.export("cognitoDomainZoneId", user_pool_domain.cloudfront_distribution_zone_id)

    return user_pool, user_pool_client, user_pool_domain
