import pulumi
import pulumi_aws as aws


def create_site_bucket_and_oac(
    *,
    stack: str,
    domain_slug: str,
    target_provider: aws.Provider,
):
    """
    Creates:
      - site content bucket (private, served via CloudFront OAC)
      - public access block
      - CloudFront Origin Access Control (SigV4)

    Returns:
      (site_bucket, oac)
    """
    site_bucket = aws.s3.Bucket(
        "siteBucket",
        bucket=f"{domain_slug}-{stack}-site",
        tags={"Project": "website", "Env": stack},
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    aws.s3.BucketPublicAccessBlock(
        "siteBucketPab",
        bucket=site_bucket.id,
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True,
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    oac = aws.cloudfront.OriginAccessControl(
        "siteOac",
        name=f"{domain_slug}-{stack}-oac",
        origin_access_control_origin_type="s3",
        signing_behavior="always",
        signing_protocol="sigv4",
        opts=pulumi.ResourceOptions(provider=target_provider),
    )

    pulumi.export("siteBucketName", site_bucket.bucket)
    pulumi.export("oacId", oac.id)

    return {
        "site_bucket": site_bucket,
        "oac": oac,
    }

def attach_cloudfront_read_policy(
    *,
    site_bucket: aws.s3.Bucket,
    dist: aws.cloudfront.Distribution,
    target_provider: aws.Provider,
):
    """
    Bucket policy: allow CloudFront distribution to read objects from the site bucket.
    Keeps the original Pulumi name 'siteBucketPolicy' stable.
    """
    bucket_policy_doc = aws.iam.get_policy_document_output(statements=[
        aws.iam.GetPolicyDocumentStatementArgs(
            sid="AllowCloudFrontRead",
            actions=["s3:GetObject"],
            resources=[site_bucket.arn.apply(lambda arn: f"{arn}/*")],
            principals=[aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                type="Service",
                identifiers=["cloudfront.amazonaws.com"],
            )],
            conditions=[aws.iam.GetPolicyDocumentStatementConditionArgs(
                test="StringEquals",
                variable="AWS:SourceArn",
                values=[dist.arn],
            )],
        )
    ])

    aws.s3.BucketPolicy(
        "siteBucketPolicy",
        bucket=site_bucket.id,
        policy=bucket_policy_doc.json,
        opts=pulumi.ResourceOptions(provider=target_provider),
    )
