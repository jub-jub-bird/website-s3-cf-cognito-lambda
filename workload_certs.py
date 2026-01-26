import pulumi
import pulumi_aws as aws


def create_workload_certs(
    *,
    stack: str,
    domain_slug: str,
    aliases: list[str],
    cognito_auth_domain: str,
    enable_custom_domain: bool,
    enable_cognito_domain: bool,
    use1_provider: aws.Provider,
):
    """
    Create ACM certificates in us-east-1 for:
      - CloudFront site aliases
      - Cognito custom domain

    Returns:
      (site_cert, site_cert_validation, auth_cert, auth_cert_validation)
    """

    # -------------------------------------------------------------------
    # Site certificate (CloudFront) in us-east-1
    # -------------------------------------------------------------------
    site_cert = aws.acm.Certificate(
        "siteCert",
        domain_name=aliases[0],
        subject_alternative_names=aliases[1:],
        validation_method="DNS",
        opts=pulumi.ResourceOptions(provider=use1_provider),
    )
    pulumi.export("siteCertArn", site_cert.arn)

    site_cert_validation_records = site_cert.domain_validation_options.apply(
        lambda opts: [
            {"name": o.resource_record_name, "type": o.resource_record_type, "value": o.resource_record_value}
            for o in (opts or [])
        ]
    )
    pulumi.export("siteCertValidationRecords", site_cert_validation_records)

    site_cert_validation = None
    if enable_custom_domain:
        site_cert_validation = aws.acm.CertificateValidation(
            "siteCertValidation",
            certificate_arn=site_cert.arn,
            validation_record_fqdns=site_cert.domain_validation_options.apply(
                lambda opts: [o.resource_record_name for o in (opts or [])]
            ),
            opts=pulumi.ResourceOptions(provider=use1_provider),
        )

    # -------------------------------------------------------------------
    # Cognito custom domain cert (CloudFront behind Cognito) in us-east-1
    # -------------------------------------------------------------------
    auth_cert = aws.acm.Certificate(
        "authCert",
        domain_name=cognito_auth_domain,
        validation_method="DNS",
        opts=pulumi.ResourceOptions(provider=use1_provider),
    )
    pulumi.export("authCertArn", auth_cert.arn)

    auth_cert_validation_records = auth_cert.domain_validation_options.apply(
        lambda opts: [
            {"name": o.resource_record_name, "type": o.resource_record_type, "value": o.resource_record_value}
            for o in (opts or [])
        ]
    )
    pulumi.export("authCertValidationRecords", auth_cert_validation_records)

    auth_cert_validation = None
    if enable_cognito_domain:
        auth_cert_validation = aws.acm.CertificateValidation(
            "authCertValidation",
            certificate_arn=auth_cert.arn,
            validation_record_fqdns=auth_cert.domain_validation_options.apply(
                lambda opts: [o.resource_record_name for o in (opts or [])]
            ),
            opts=pulumi.ResourceOptions(provider=use1_provider),
        )

    return site_cert, site_cert_validation, auth_cert, auth_cert_validation
