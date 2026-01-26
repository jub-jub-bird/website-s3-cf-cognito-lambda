# network_dns.py
import pulumi
import pulumi_aws as aws
from helpers import workload_aliases, _slug, _r53_import_id
import re

def deploy_network_dns(
    *,
    cfg: pulumi.Config,
    org: str,
    project: str,
    stack: str,
    hosted_zone_id: str | None,
    hosted_zone_name: str | None,
    adopt_existing_records: bool,
    target_provider: aws.Provider,
):
    if stack != "network":
        return

    if not hosted_zone_id or not hosted_zone_name:
        raise Exception("network stack requires hostedZoneId and hostedZoneName config.")
        
    protect_records = cfg.get_bool("protectDnsRecords")
    if protect_records is None:
        protect_records = True

    prod_ref = pulumi.StackReference(f"{org}/{project}/prod")
    staging_ref = pulumi.StackReference(f"{org}/{project}/staging")

    def upsert_cname_records(prefix: str, records_out: pulumi.Output):
        def _mk(recs):
            if not recs:
                return []
            made = []
            for r in recs:
                r_name = (r.get("name") or "").rstrip(".")
                r_type = (r.get("type") or "CNAME").upper()
                r_val = r.get("value")
                if not r_name or not r_val:
                    continue

                res_name = f"{prefix}-{_slug(r_name)}-{r_type.lower()}"
                import_id = _r53_import_id(hosted_zone_id, r_name, r_type)

                made.append(
                    aws.route53.Record(
                        res_name,
                        zone_id=hosted_zone_id,
                        name=r_name,
                        type=r_type,
                        ttl=300,
                        records=[r_val],
                        opts=pulumi.ResourceOptions(
                            provider=target_provider,
                            import_=import_id if adopt_existing_records else None,
                            protect=protect_records,
                        ),
                    )
                )
            return made

        return records_out.apply(_mk)

    # Cert validations (CloudFront / Cognito) in us-east-1
    upsert_cname_records("prod-site-certval", prod_ref.get_output("siteCertValidationRecords"))
    upsert_cname_records("staging-site-certval", staging_ref.get_output("siteCertValidationRecords"))

    upsert_cname_records("prod-auth-certval", prod_ref.get_output("authCertValidationRecords"))
    upsert_cname_records("staging-auth-certval", staging_ref.get_output("authCertValidationRecords"))

    # Optional: API GW regional cert validation (exists only if authApiCustomDomain configured)
    upsert_cname_records("prod-authapi-certval", prod_ref.get_output("authApiRegionalCertValidationRecords"))
    upsert_cname_records("staging-authapi-certval", staging_ref.get_output("authApiRegionalCertValidationRecords"))

    # -------------------------------------------------------------------
    # API Gateway custom domain alias records (A/AAAA)
    # -------------------------------------------------------------------
    def upsert_authapi_aliases(env: str, ref: pulumi.StackReference):
        auth_api_domain = ref.get_output("authApiRegionalDomainName")
        auth_api_target = ref.get_output("authApiRegionalTargetDomainName")
        auth_api_zone = ref.get_output("authApiRegionalHostedZoneId")

        def _mk(args):
            (domain_name, target_name, zone_id_val) = args
            if not domain_name or not target_name or not zone_id_val:
                return []

            domain_name = str(domain_name).rstrip(".")
            target_name = str(target_name).rstrip(".")
            zone_id_val = str(zone_id_val)

            resources = []
            for rtype in ("A", "AAAA"):
                res_name = f"{env}-authapi-{_slug(domain_name)}-{rtype.lower()}"
                import_id = _r53_import_id(hosted_zone_id, domain_name, rtype)

                resources.append(
                    aws.route53.Record(
                        res_name,
                        zone_id=hosted_zone_id,
                        name=domain_name,
                        type=rtype,
                        aliases=[aws.route53.RecordAliasArgs(
                            name=target_name,
                            zone_id=zone_id_val,
                            evaluate_target_health=False,
                        )],
                        opts=pulumi.ResourceOptions(
                            provider=target_provider,
                            import_=import_id if adopt_existing_records else None,
                            protect=protect_records,
                        ),
                    )
                )
            return resources

        return pulumi.Output.all(auth_api_domain, auth_api_target, auth_api_zone).apply(_mk)

    upsert_authapi_aliases("prod", prod_ref)
    upsert_authapi_aliases("staging", staging_ref)

    # -------------------------------------------------------------------
    # Site aliases -> CloudFront (A/AAAA)
    # -------------------------------------------------------------------
    def upsert_site_aliases(env: str, ref: pulumi.StackReference):
        enabled = ref.get_output("customDomainEnabled")
        aliases_out = ref.get_output("aliases")
        cf_domain = ref.get_output("cloudFrontDomain")
        cf_zone = ref.get_output("cloudFrontZoneId")

        def _mk(args):
            (is_enabled, alias_list, dname, z) = args
            if not is_enabled or not alias_list or not dname or not z:
                return []
            resources = []
            for alias in alias_list:
                alias = str(alias).rstrip(".")
                for rtype in ("A", "AAAA"):
                    res_name = f"{env}-site-{_slug(alias)}-{rtype.lower()}"
                    import_id = _r53_import_id(hosted_zone_id, alias, rtype)
                    resources.append(
                        aws.route53.Record(
                            res_name,
                            zone_id=hosted_zone_id,
                            name=alias,
                            type=rtype,
                            aliases=[aws.route53.RecordAliasArgs(
                                name=str(dname).rstrip("."),
                                zone_id=str(z),
                                evaluate_target_health=False,
                            )],
                            opts=pulumi.ResourceOptions(
                                provider=target_provider,
                                import_=import_id if adopt_existing_records else None,
                                protect=protect_records,
                            ),
                        )
                    )
            return resources

        return pulumi.Output.all(enabled, aliases_out, cf_domain, cf_zone).apply(_mk)

    upsert_site_aliases("prod", prod_ref)
    upsert_site_aliases("staging", staging_ref)

    # -------------------------------------------------------------------
    # Cognito aliases -> Cognito hosted UI CloudFront distro (A/AAAA)
    # -------------------------------------------------------------------
    def upsert_cognito_aliases(env: str, ref: pulumi.StackReference):
        enabled = ref.get_output("enableCognitoDomain")
        cname = ref.get_output("cognitoDomainName")
        dname = ref.get_output("cognitoDomainCloudFront")
        z = ref.get_output("cognitoDomainZoneId")

        def _mk(args):
            (is_enabled, domain_name, dist_domain, zone_id_val) = args
            if not is_enabled or not domain_name or not dist_domain or not zone_id_val:
                return []
            domain_name = str(domain_name).rstrip(".")
            resources = []
            for rtype in ("A", "AAAA"):
                res_name = f"{env}-cognito-{_slug(domain_name)}-{rtype.lower()}"
                import_id = _r53_import_id(hosted_zone_id, domain_name, rtype)
                resources.append(
                    aws.route53.Record(
                        res_name,
                        zone_id=hosted_zone_id,
                        name=domain_name,
                        type=rtype,
                        aliases=[aws.route53.RecordAliasArgs(
                            name=str(dist_domain).rstrip("."),
                            zone_id=str(zone_id_val),
                            evaluate_target_health=False,
                        )],
                        opts=pulumi.ResourceOptions(
                            provider=target_provider,
                            import_=import_id if adopt_existing_records else None,
                            protect=protect_records,
                        ),
                    )
                )
            return resources

        return pulumi.Output.all(enabled, cname, dname, z).apply(_mk)

    upsert_cognito_aliases("prod", prod_ref)
    upsert_cognito_aliases("staging", staging_ref)
    
    pulumi.export("hostedZoneName", hosted_zone_name)
    pulumi.export("hostedZoneId", hosted_zone_id)
