import pulumi
import pulumi_aws as aws


def create_cloudfront_distribution(
    *,
    # identity
    stack: str,
    domain_slug: str,
    # site settings
    default_root_object: str,
    enable_custom_domain: bool,
    aliases: list[str],
    # origins
    site_origin: dict,
    auth_origin: dict,
    # behavior components
    behavior: dict,
    # provider
    target_provider: aws.Provider,
):
    """
    Create CloudFront distribution for:
      - / (public)
      - /private/* (signed cookies)
      - /auth/* -> API Gateway origin
    """

    site_bucket: aws.s3.Bucket = site_origin["site_bucket"]
    oac: aws.cloudfront.OriginAccessControl = site_origin["oac"]

    auth_origin_domain_for_cf = auth_origin["domain_name"]
    auth_origin_path_for_cf = auth_origin["origin_path"]
    origin_verify_secret = auth_origin["origin_verify_secret"]

    viewer_cert: aws.cloudfront.DistributionViewerCertificateArgs = behavior["viewer_cert"]
    security_headers_policy: aws.cloudfront.ResponseHeadersPolicy = behavior["security_headers_policy"]
    cf_function: aws.cloudfront.Function = behavior["cf_function"]
    cf_key_group: aws.cloudfront.KeyGroup = behavior["cf_key_group"]
    caching_disabled = behavior["caching_disabled"]
    all_viewer_except_host = behavior["all_viewer_except_host"]

    dist = aws.cloudfront.Distribution(
        "siteDist",
        enabled=True,
        default_root_object=default_root_object,
        aliases=aliases if enable_custom_domain else None,
        origins=[
            aws.cloudfront.DistributionOriginArgs(
                domain_name=site_bucket.bucket_regional_domain_name,
                origin_id="s3-site-origin",
                origin_access_control_id=oac.id,
            ),
            aws.cloudfront.DistributionOriginArgs(
                domain_name=auth_origin_domain_for_cf,
                origin_id="auth-api-origin",
                origin_path=auth_origin_path_for_cf,
                custom_headers=[
                    aws.cloudfront.DistributionOriginCustomHeaderArgs(
                        name="X-Origin-Verify",
                        value=origin_verify_secret,
                    )
                ],
                custom_origin_config=aws.cloudfront.DistributionOriginCustomOriginConfigArgs(
                    origin_protocol_policy="https-only",
                    http_port=80,
                    https_port=443,
                    origin_ssl_protocols=["TLSv1.2"],
                ),
            ),
        ],
        custom_error_responses=[
            aws.cloudfront.DistributionCustomErrorResponseArgs(
                error_code=403,
                response_code=200,
                response_page_path="/session-expired.html",
                error_caching_min_ttl=0,
            )
        ],
        default_cache_behavior=aws.cloudfront.DistributionDefaultCacheBehaviorArgs(
            target_origin_id="s3-site-origin",
            viewer_protocol_policy="redirect-to-https",
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            cached_methods=["GET", "HEAD"],
            compress=True,
            response_headers_policy_id=security_headers_policy.id,
            trusted_key_groups=[],
            function_associations=[
                aws.cloudfront.DistributionDefaultCacheBehaviorFunctionAssociationArgs(
                    event_type="viewer-request",
                    function_arn=cf_function.arn,
                )
            ],
            forwarded_values=aws.cloudfront.DistributionDefaultCacheBehaviorForwardedValuesArgs(
                query_string=False,
                cookies=aws.cloudfront.DistributionDefaultCacheBehaviorForwardedValuesCookiesArgs(
                    forward="none"
                ),
            ),
        ),
        ordered_cache_behaviors=[
            aws.cloudfront.DistributionOrderedCacheBehaviorArgs(
                path_pattern="/auth/*",
                target_origin_id="auth-api-origin",
                viewer_protocol_policy="redirect-to-https",
                allowed_methods=["GET", "HEAD", "OPTIONS"],
                cached_methods=["GET", "HEAD"],
                compress=True,
                cache_policy_id=caching_disabled.id,
                origin_request_policy_id=all_viewer_except_host.id,
            ),
            aws.cloudfront.DistributionOrderedCacheBehaviorArgs(
                path_pattern="/private/*",
                target_origin_id="s3-site-origin",
                viewer_protocol_policy="redirect-to-https",
                allowed_methods=["GET", "HEAD", "OPTIONS"],
                cached_methods=["GET", "HEAD"],
                compress=True,
                response_headers_policy_id=security_headers_policy.id,
                trusted_key_groups=[cf_key_group.id],
                function_associations=[
                    aws.cloudfront.DistributionOrderedCacheBehaviorFunctionAssociationArgs(
                        event_type="viewer-request",
                        function_arn=cf_function.arn,
                    )
                ],
                forwarded_values=aws.cloudfront.DistributionOrderedCacheBehaviorForwardedValuesArgs(
                    query_string=False,
                    cookies=aws.cloudfront.DistributionDefaultCacheBehaviorForwardedValuesCookiesArgs(
                        forward="none"
                    ),
                ),
            ),
        ],
        restrictions=aws.cloudfront.DistributionRestrictionsArgs(
            geo_restriction=aws.cloudfront.DistributionRestrictionsGeoRestrictionArgs(
                restriction_type="none"
            )
        ),
        viewer_certificate=viewer_cert,
        price_class="PriceClass_100",
        logging_config=None,
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    pulumi.export("cloudFrontDomain", dist.domain_name)
    pulumi.export("cloudFrontZoneId", dist.hosted_zone_id)
    pulumi.export("cloudFrontDistId", dist.id)
    pulumi.export("cloudFrontDistArn", dist.arn)

    return dist
