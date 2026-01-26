import pulumi
import pulumi_aws as aws


def create_auth_lambdas(
    *,
    cfg: pulumi.Config,
    aliases: list[str],
    domain_slug: str,
    stack: str,
    allowed_hosts_csv: str,
    cognito_auth_domain: str,
    redirect_path: str,
    post_login_path: str,
    cookie_domain_base: str | None,
    user_pool_client: aws.cognito.UserPoolClient,
    cloudfront_key_pair_id: pulumi.Input[str],
    cloudfront_private_key_pem: pulumi.Input[str],
    origin_verify_secret,
    callback_provider: aws.Provider,
    log_retention_days: int,
):
    """
    Creates:
      - Lambda IAM role (+ basic exec policy)
      - authLoginFn
      - authCallbackFn
      - authLogoutFn

    Returns:
      (lambda_role, login_lambda, callback_lambda, logout_lambda, cookie_ttl_seconds)
    """
    name_prefix = f"{domain_slug}-{stack}"
    # -------------------------------------------------------------------
    # Lambda: /auth/* role
    # -------------------------------------------------------------------
    lambda_role = aws.iam.Role(
        "authCallbackRole",
        assume_role_policy=aws.iam.get_policy_document_output(statements=[
            aws.iam.GetPolicyDocumentStatementArgs(
                actions=["sts:AssumeRole"],
                principals=[aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                    type="Service",
                    identifiers=["lambda.amazonaws.com"],
                )],
            )
        ]).json,
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    aws.iam.RolePolicyAttachment(
        "authCallbackBasicExec",
        role=lambda_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )

    cookie_ttl_seconds = int(cfg.get("cookieTtlSeconds") or "3600")
    state_secret = cfg.require_secret("stateSecret")

    # NOTE: strings below are copied verbatim from your workload file
    login_lambda_code = r"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse



def _enforce_origin_secret(event):
    expected = os.environ.get("ORIGIN_VERIFY_SECRET", "").strip()
    if not expected:
        # Fail closed if misconfigured
        return False

    headers = event.get("headers") or {}

    # API Gateway headers can be any case
    provided = (
        headers.get("X-Origin-Verify")
        or headers.get("x-origin-verify")
        or ""
    ).strip()
    print("ORIGIN_VERIFY provided:", bool(provided), "expected_present:", bool(expected))

    return provided == expected

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _sign_state(payload_json: str, secret: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256).digest()
    return _b64url(sig)


def handler(event, context):
    rid = getattr(context, "aws_request_id", "")
    print(f"[login] START rid={rid}")

    try:
        # Basic event visibility (don’t print whole body if you ever add it)
        print("[login] event keys:", list((event or {}).keys()))
        headers = (event.get("headers") or {})
        qs = (event.get("queryStringParameters") or {})

        print("[login] headers present:", sorted(list(headers.keys()))[:20], "...")
        print("[login] queryStringParameters:", qs)

        # Enforce origin secret first
        ok = _enforce_origin_secret(event)
        print("[login] origin secret ok:", ok)
        if not ok:
            print("[login] FORBIDDEN (origin secret mismatch)")
            return {
                "statusCode": 403,
                "headers": {"Cache-Control": "no-store"},
                "body": "Forbidden",
            }

        # Pull inputs
        requested_host_raw = (qs.get("host") or "").strip().lower()
        print("[login] requested_host_raw:", requested_host_raw)

        allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS") or ""
        site_host_fallback_raw = (os.environ.get("SITE_HOST") or "").strip().lower()

        print("[login] SITE_HOST raw:", site_host_fallback_raw)
        print("[login] ALLOWED_HOSTS raw:", allowed_hosts_raw)

        allowed_hosts = set(
            h.strip().lower()
            for h in allowed_hosts_raw.split(",")
            if h.strip()
        )
        print("[login] allowed_hosts parsed:", sorted(list(allowed_hosts)))

        def _canonicalize(h: str) -> str:
            h = (h or "").strip().lower().rstrip(".")
            if h.startswith("www."):
                return h[len("www."):]
            return h

        requested_host = requested_host_raw
        host = _canonicalize(requested_host_raw)
        site_host_fallback = _canonicalize(site_host_fallback_raw)

        print("[login] canonical requested_host:", host)
        print("[login] canonical site_host_fallback:", site_host_fallback)

        # Validate allow-list using canonical forms too
        allowed_hosts_canon = set(_canonicalize(h) for h in allowed_hosts)
        print("[login] allowed_hosts_canon:", sorted(list(allowed_hosts_canon)))

        if not host or host not in allowed_hosts_canon:
            print("[login] host not allowed -> fallback")
            host = site_host_fallback

        print("[login] selected host:", host)

        # If user came in as www.*, bounce to canonical host first
        if requested_host and requested_host.startswith("www.") and host:
            bounce = "https://" + host + "/auth/login?host=" + urllib.parse.quote(host, safe="")
            print("[login] www bounce ->", bounce)
            return {
                "statusCode": 302,
                "headers": {
                    "Location": bounce,
                    "Cache-Control": "no-store",
                },
                "body": "",
            }

        # Required env vars for building Hosted UI URL
        cognito_domain = os.environ.get("COGNITO_DOMAIN", "")
        client_id = os.environ.get("COGNITO_CLIENT_ID", "")
        redirect_path = os.environ.get("REDIRECT_PATH", "/auth/callback")
        state_secret_present = bool(os.environ.get("STATE_SECRET"))

        print("[login] COGNITO_DOMAIN present:", bool(cognito_domain), "value:", cognito_domain)
        print("[login] COGNITO_CLIENT_ID present:", bool(client_id), "len:", len(client_id))
        print("[login] REDIRECT_PATH:", redirect_path)
        print("[login] STATE_SECRET present:", state_secret_present)

        if not cognito_domain or not client_id or not state_secret_present:
            print("[login] MISCONFIG: missing required env var(s)")
            return {
                "statusCode": 500,
                "headers": {"Cache-Control": "no-store"},
                "body": "Server misconfiguration (missing cognito env vars)",
            }

        now = int(time.time())
        payload = {"h": host, "t": now}
        payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        state = _b64url(payload_json.encode("utf-8")) + "." + _sign_state(payload_json, os.environ["STATE_SECRET"])

        redirect_uri = "https://" + host + redirect_path
        print("[login] redirect_uri:", redirect_uri)
        print("[login] state len:", len(state))

        location = (
            "https://" + cognito_domain
            + "/login?response_type=code"
            + "&client_id=" + urllib.parse.quote(client_id, safe="")
            + "&redirect_uri=" + urllib.parse.quote(redirect_uri, safe="")
            + "&scope=" + urllib.parse.quote("openid email profile", safe="")
            + "&state=" + urllib.parse.quote(state, safe="")
        )

        print("[login] location (Hosted UI):", location[:500] + ("...(truncated)" if len(location) > 500 else ""))

        resp = {
            "statusCode": 302,
            "headers": {
                "Location": location,
                "Cache-Control": "no-store",
            },
            "body": "",
        }
        print("[login] END rid=", rid)
        return resp

    except Exception as e:
        import traceback
        print("[login] EXCEPTION:", repr(e))
        print(traceback.format_exc())
        return {
            "statusCode": 500,
            "headers": {"Cache-Control": "no-store"},
            "body": "Login error",
        }


"""

    callback_lambda_code = r"""
import base64
import hashlib
import json
import os
import time
import urllib.parse
import urllib.request
import traceback
import hmac

def _enforce_origin_secret(event):
    expected = os.environ.get("ORIGIN_VERIFY_SECRET", "").strip()
    if not expected:
        # Fail closed if misconfigured
        return False

    headers = event.get("headers") or {}

    # API Gateway headers can be any case
    provided = (
        headers.get("X-Origin-Verify")
        or headers.get("x-origin-verify")
        or ""
    ).strip()
    print("ORIGIN_VERIFY provided:", bool(provided), "expected_present:", bool(expected))

    return provided == expected

def _log(msg):
    print(msg)

def _safe(obj, max_len=8000):
    try:
        s = json.dumps(obj, default=str)
    except Exception:
        s = str(obj)
    if len(s) > max_len:
        return s[:max_len] + "...(truncated)"
    return s

def _b64url_decode_json(s: str):
    # base64url decode with padding
    pad = "=" * ((4 - len(s) % 4) % 4)
    raw = base64.urlsafe_b64decode((s + pad).encode("utf-8"))
    return json.loads(raw.decode("utf-8"))

def _make_user_cookie_value(id_token: str) -> str:
    # id_token is a JWT: header.payload.signature
    parts = (id_token or "").split(".")
    if len(parts) < 2:
        return ""

    payload = _b64url_decode_json(parts[1])

    # keep it minimal (avoid dumping the whole token)
    user = {
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "username": payload.get("cognito:username") or payload.get("username"),
        "groups": payload.get("cognito:groups") or [],
    }

    # compact json -> base64url (no padding)
    blob = json.dumps(user, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(blob).decode("utf-8").rstrip("=")

def _cf_safe_b64(data: bytes) -> str:
    # CloudFront signed cookie encoding:
    # base64, then + -> -, = -> _, / -> ~
    s = base64.b64encode(data).decode("utf-8")
    return s.replace("+", "-").replace("=", "_").replace("/", "~")

def _token_exchange(cognito_domain: str, client_id: str, client_secret: str, code: str, redirect_uri: str):
    token_url = "https://" + cognito_domain + "/oauth2/token"
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
    }).encode("utf-8")

    basic = base64.b64encode((client_id + ":" + client_secret).encode("utf-8")).decode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=body,
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "authorization": "Basic " + basic,
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw)


class _DER:
    def __init__(self, b: bytes):
        self.b = b
        self.i = 0

    def _read_byte(self) -> int:
        if self.i >= len(self.b):
            raise ValueError("DER: unexpected EOF")
        v = self.b[self.i]
        self.i += 1
        return v

    def _read_len(self) -> int:
        n = self._read_byte()
        if n < 0x80:
            return n
        num = n & 0x7F
        if num == 0:
            raise ValueError("DER: indefinite length not supported")
        val = 0
        for _ in range(num):
            val = (val << 8) | self._read_byte()
        return val

    def read_tlv(self):
        tag = self._read_byte()
        ln = self._read_len()
        start = self.i
        end = start + ln
        if end > len(self.b):
            raise ValueError("DER: length beyond buffer")
        self.i = end
        return tag, self.b[start:end]

    @staticmethod
    def as_der(buf: bytes):
        return _DER(buf)

    @staticmethod
    def read_int_from_integer_bytes(integer_bytes: bytes) -> int:
        v = integer_bytes
        while len(v) > 1 and v[0] == 0x00:
            v = v[1:]
        out = 0
        for c in v:
            out = (out << 8) | c
        return out


def _pem_to_der(pem: str) -> bytes:
    pem = pem.replace("\\n", "\n").strip()
    lines = [ln.strip() for ln in pem.splitlines() if ln and not ln.startswith("-----")]
    return base64.b64decode("".join(lines))


def _load_rsa_private_key_n_d(private_pem: str):
    der = _pem_to_der(private_pem)
    d = _DER.as_der(der)
    tag, content = d.read_tlv()
    if tag != 0x30:
        raise ValueError("DER: expected SEQUENCE")

    # Try PKCS#1 first
    try:
        s = _DER.as_der(content)
        s.read_tlv()  # version
        t, n_bytes = s.read_tlv()
        if t != 0x02:
            raise ValueError("PKCS1: expected n INTEGER")
        s.read_tlv()  # e
        t, d_bytes = s.read_tlv()
        if t != 0x02:
            raise ValueError("PKCS1: expected d INTEGER")
        n = _DER.read_int_from_integer_bytes(n_bytes)
        dd = _DER.read_int_from_integer_bytes(d_bytes)
        return n, dd
    except Exception:
        pass

    # PKCS#8
    s = _DER.as_der(content)
    s.read_tlv()  # version
    s.read_tlv()  # algId
    t, pk_octets = s.read_tlv()
    if t != 0x04:
        raise ValueError("PKCS8: expected OCTET STRING privateKey")

    inner = _DER.as_der(pk_octets)
    t, inner_seq = inner.read_tlv()
    if t != 0x30:
        raise ValueError("PKCS8: expected RSAPrivateKey SEQUENCE")

    rs = _DER.as_der(inner_seq)
    rs.read_tlv()  # version
    t, n_bytes = rs.read_tlv()
    rs.read_tlv()  # e
    t2, d_bytes = rs.read_tlv()

    n = _DER.read_int_from_integer_bytes(n_bytes)
    dd = _DER.read_int_from_integer_bytes(d_bytes)
    return n, dd

_SHA1_DIGESTINFO_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")

def _rsa_sha1_sign(private_key_pem: str, message: bytes) -> bytes:
    n, d = _load_rsa_private_key_n_d(private_key_pem)
    k = (n.bit_length() + 7) // 8

    h = hashlib.sha1(message).digest()
    t = _SHA1_DIGESTINFO_PREFIX + h

    if k < len(t) + 11:
        raise ValueError("RSA: intended encoded message length too short")

    ps = b"\xff" * (k - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t

    m = int.from_bytes(em, "big")
    sig = pow(m, d, n)
    return sig.to_bytes(k, "big")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _verify_and_extract_state(state: str, secret: str, max_age_seconds: int = 600):
    if not state or "." not in state:
        return None

    try:
        payload_b64, sig_b64 = state.split(".", 1)
        payload_json = _b64url_decode(payload_b64).decode("utf-8")

        expected_sig = hmac.new(secret.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256).digest()
        expected_sig_b64 = _b64url_encode(expected_sig)

        # constant-time compare
        if not hmac.compare_digest(expected_sig_b64, sig_b64):
            return None

        payload = json.loads(payload_json)
        host = (payload.get("h") or "").strip().lower()
        ts = int(payload.get("t") or 0)

        now = int(time.time())
        if ts <= 0 or now - ts > max_age_seconds:
            return None

        return host
    except Exception:
        return None


def handler(event, context):
    rid = getattr(context, "aws_request_id", "")
    print(f"[authcb] START rid={rid}")

    try:
        # Basic visibility
        print("[authcb] event keys:", list((event or {}).keys()))
        headers = (event.get("headers") or {})
        qs = (event.get("queryStringParameters") or {})

        print("[authcb] headers keys sample:", sorted(list(headers.keys()))[:25], "...")
        print("[authcb] qs:", qs)

        # Origin verify first
        ok = _enforce_origin_secret(event)
        print("[authcb] origin secret ok:", ok)
        if not ok:
            print("[authcb] FORBIDDEN (origin secret mismatch)")
            return {
                "statusCode": 403,
                "headers": {"Cache-Control": "no-store"},
                "body": "Forbidden",
            }

        code = (qs.get("code") or "").strip()
        state = (qs.get("state") or "").strip()

        print("[authcb] code_present:", bool(code))
        print("[authcb] state_present:", bool(state), "len:", len(state))

        if not code:
            print("[authcb] ERROR missing code; returning 400")
            return {
                "statusCode": 400,
                "headers": {"Cache-Control": "no-store"},
                "body": "Missing ?code",
            }

        # Env sanity (don’t print secrets, just presence)
        cognito_domain = os.environ.get("COGNITO_DOMAIN", "")
        client_id = os.environ.get("COGNITO_CLIENT_ID", "")
        client_secret_present = bool(os.environ.get("COGNITO_CLIENT_SECRET"))
        redirect_path = os.environ.get("REDIRECT_PATH", "/auth/callback")
        site_host_fallback = (os.environ.get("SITE_HOST") or "").strip().lower()
        key_pair_id = os.environ.get("CF_KEY_PAIR_ID", "")
        private_key_present = bool(os.environ.get("CF_PRIVATE_KEY_PEM"))
        state_secret = (os.environ.get("STATE_SECRET", "") or "").strip()
        ttl_raw = os.environ.get("COOKIE_TTL_SECONDS", "3600")
        cookie_domain_base = (os.environ.get("COOKIE_DOMAIN_BASE") or "").strip().lstrip(".")
        post_login_path = os.environ.get("POST_LOGIN_PATH", "/private/start.html")

        print("[authcb] COGNITO_DOMAIN present:", bool(cognito_domain), "value:", cognito_domain)
        print("[authcb] COGNITO_CLIENT_ID present:", bool(client_id), "len:", len(client_id))
        print("[authcb] COGNITO_CLIENT_SECRET present:", client_secret_present)
        print("[authcb] REDIRECT_PATH:", redirect_path)
        print("[authcb] SITE_HOST:", site_host_fallback)
        print("[authcb] CF_KEY_PAIR_ID present:", bool(key_pair_id), "len:", len(key_pair_id))
        print("[authcb] CF_PRIVATE_KEY_PEM present:", private_key_present)
        print("[authcb] STATE_SECRET present:", bool(state_secret))
        print("[authcb] COOKIE_TTL_SECONDS raw:", ttl_raw)
        print("[authcb] COOKIE_DOMAIN_BASE:", cookie_domain_base)
        print("[authcb] POST_LOGIN_PATH:", post_login_path)

        if not cognito_domain or not client_id or not client_secret_present or not key_pair_id or not private_key_present:
            print("[authcb] MISCONFIG: required env var(s) missing")
            return {
                "statusCode": 500,
                "headers": {"Cache-Control": "no-store"},
                "body": "Server misconfiguration (missing env vars)",
            }

        # Allowed hosts
        allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS") or ""
        allowed_hosts = set(
            h.strip().lower()
            for h in allowed_hosts_raw.split(",")
            if h.strip()
        )
        print("[authcb] ALLOWED_HOSTS raw:", allowed_hosts_raw)
        print("[authcb] allowed_hosts parsed:", sorted(list(allowed_hosts)))

        # forwarded host
        xfh = headers.get("X-Forwarded-Host") or headers.get("x-forwarded-host") or ""
        xfh_host = (xfh or "").strip().lower()
        print("[authcb] X-Forwarded-Host:", xfh_host)

        # Signed-state enforcement
        state_raw = state
        print("[authcb] STATE_RAW:", state_raw[:200] + ("...(trunc)" if len(state_raw) > 200 else ""))
        print("[authcb] STATE_HAS_DOT:", "." in state_raw)
        print("[authcb] STATE_SECRET_PRESENT:", bool(state_secret))

        signed_host = None

        if state_secret and "." in state_raw:
            print("[authcb] state path: SIGNED")
            signed_host = _verify_and_extract_state(state_raw, state_secret, max_age_seconds=600)
            print("[authcb] SIGNED_HOST:", signed_host)

            if not signed_host:
                print("[authcb] invalid state: signed_host None")
                return {
                    "statusCode": 400,
                    "headers": {"Cache-Control": "no-store"},
                    "body": "Invalid state",
                }

            if signed_host not in allowed_hosts:
                print("[authcb] invalid state: signed_host not in allowlist")
                return {
                    "statusCode": 400,
                    "headers": {"Cache-Control": "no-store"},
                    "body": "Invalid state",
                }

            viewer_host = signed_host

        else:
            print("[authcb] state path: FALLBACK")
            if xfh_host and xfh_host in allowed_hosts:
                viewer_host = xfh_host
                print("[authcb] viewer_host from XFH:", viewer_host)
            else:
                state_host = (state_raw or "").strip().lower()
                if state_host and state_host in allowed_hosts:
                    viewer_host = state_host
                    print("[authcb] viewer_host from raw state:", viewer_host)
                else:
                    viewer_host = site_host_fallback
                    print("[authcb] viewer_host fallback SITE_HOST:", viewer_host)

        if not viewer_host:
            print("[authcb] ERROR: viewer_host empty after selection")
            return {
                "statusCode": 500,
                "headers": {"Cache-Control": "no-store"},
                "body": "Server error (no viewer host)",
            }

        redirect_uri = "https://" + viewer_host + redirect_path
        print("[authcb] redirect_uri:", redirect_uri)

        # Token exchange
        print("[authcb] token exchange: START")
        tokens = _token_exchange(
            cognito_domain,
            client_id,
            os.environ["COGNITO_CLIENT_SECRET"],
            code,
            redirect_uri
        )
        print("[authcb] token exchange: DONE keys:", list((tokens or {}).keys()))

        id_token = tokens.get("id_token", "")
        access_token_present = bool(tokens.get("access_token"))
        refresh_token_present = bool(tokens.get("refresh_token"))

        print("[authcb] id_token present:", bool(id_token), "len:", len(id_token))
        print("[authcb] access_token present:", access_token_present)
        print("[authcb] refresh_token present:", refresh_token_present)

        user_cookie_val = _make_user_cookie_value(id_token)
        print("[authcb] ml_user prepared:", bool(user_cookie_val), "len:", len(user_cookie_val))

        # TTL parsing
        try:
            ttl = int(ttl_raw)
        except Exception:
            ttl = 3600
            print("[authcb] WARNING: invalid COOKIE_TTL_SECONDS -> default 3600")

        expires = int(time.time()) + ttl
        print("[authcb] ttl:", ttl, "expires_epoch:", expires)

        # Canonical host logic (Option A)
        incoming_host = viewer_host
        canonical_host = incoming_host
        if incoming_host.startswith("www."):
            canonical_host = incoming_host[len("www."):]
        print("[authcb] incoming_host:", incoming_host, "canonical_host:", canonical_host)

        # Policy & signing
        resource = "https://" + canonical_host + "/*"
        policy_obj = {
            "Statement": [
                {
                    "Resource": resource,
                    "Condition": {"DateLessThan": {"AWS:EpochTime": expires}},
                }
            ]
        }
        policy = json.dumps(policy_obj, separators=(",", ":")).encode("utf-8")
        print("[authcb] policy resource:", resource, "policy_len:", len(policy))

        sig = _rsa_sha1_sign(os.environ["CF_PRIVATE_KEY_PEM"], policy)
        sig_b64 = _cf_safe_b64(sig)
        policy_b64 = _cf_safe_b64(policy)
        print("[authcb] sign OK sig_len:", len(sig), "sig_b64_len:", len(sig_b64), "policy_b64_len:", len(policy_b64))

        # Cookie domain rules
        # CloudFront cookies host-only (no Domain=)
        # ml_user optional Domain= only if base matches canonical host
        user_domain_attr = ""
        if cookie_domain_base and cookie_domain_base == canonical_host:
            user_domain_attr = "; Domain=" + cookie_domain_base

        print("[authcb] cookie_domain_base:", cookie_domain_base)
        print("[authcb] user_domain_attr set:", bool(user_domain_attr), "value:", user_domain_attr)

        cookies = [
            "CloudFront-Policy=" + policy_b64 + "; Path=/; Secure; HttpOnly; SameSite=Lax",
            "CloudFront-Signature=" + sig_b64 + "; Path=/; Secure; HttpOnly; SameSite=Lax",
            "CloudFront-Key-Pair-Id=" + key_pair_id + "; Path=/; Secure; HttpOnly; SameSite=Lax",
        ]

        if user_cookie_val:
            cookies.append(
                "ml_user=" + user_cookie_val
                + user_domain_attr
                + "; Path=/"
                + "; Max-Age=" + str(ttl)
                + "; Secure"
                + "; SameSite=Lax"
            )

        print("[authcb] cookies count:", len(cookies))
        # Print cookie names only (safe)
        print("[authcb] cookie names:", [c.split("=", 1)[0] for c in cookies])

        # Redirect location
        dest_path = post_login_path
        if canonical_host != incoming_host:
            location = "https://" + canonical_host + dest_path
            print("[authcb] redirect absolute to canonical:", location)
        else:
            location = dest_path
            print("[authcb] redirect relative:", location)

        resp = {
            "statusCode": 302,
            "headers": {"Location": location, "Cache-Control": "no-store"},
            "multiValueHeaders": {"Set-Cookie": cookies},
            "body": "",
        }

        print(f"[authcb] END rid={rid}")
        return resp

    except Exception as e:
        import traceback
        print("[authcb] EXCEPTION:", repr(e))
        print(traceback.format_exc())
        return {
            "statusCode": 500,
            "headers": {"Cache-Control": "no-store"},
            "body": "Callback error",
        }


"""

    logout_lambda_code = r"""
import os
import urllib.parse

def _enforce_origin_secret(event):
    expected = os.environ.get("ORIGIN_VERIFY_SECRET", "").strip()
    if not expected:
        # Fail closed if misconfigured
        return False

    headers = event.get("headers") or {}

    # API Gateway headers can be any case
    provided = (
        headers.get("X-Origin-Verify")
        or headers.get("x-origin-verify")
        or ""
    ).strip()
    print("ORIGIN_VERIFY provided:", bool(provided), "expected_present:", bool(expected))


    return provided == expected


def _expire_cookie(name: str, domain_attr: str, http_only: bool) -> str:
    parts = [
        f"{name}=",
        domain_attr,
        "; Path=/",
        "; Max-Age=0",
        "; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        "; Secure",
        "; SameSite=Lax",
    ]
    if http_only:
        parts.append("; HttpOnly")
    return "".join(parts)

def handler(event, context):
    rid = getattr(context, "aws_request_id", "")
    print(f"[authlogout] START rid={rid}")

    try:
        # Basic visibility
        print("[authlogout] event keys:", list((event or {}).keys()))
        headers = (event.get("headers") or {})
        qs = (event.get("queryStringParameters") or {})

        print("[authlogout] headers keys sample:", sorted(list(headers.keys()))[:25], "...")
        print("[authlogout] qs:", qs)

        # Origin verification
        ok = _enforce_origin_secret(event)
        print("[authlogout] origin secret ok:", ok)
        if not ok:
            print("[authlogout] FORBIDDEN (origin secret mismatch)")
            return {
                "statusCode": 403,
                "headers": {"Cache-Control": "no-store"},
                "body": "Forbidden",
            }

        # Env vars (presence only where sensitive)
        cookie_domain_base = (os.environ.get("COOKIE_DOMAIN_BASE") or "").strip().lstrip(".")
        cognito_domain = os.environ.get("COGNITO_DOMAIN", "")
        client_id = os.environ.get("COGNITO_CLIENT_ID", "")
        site_host_fallback = (os.environ.get("SITE_HOST") or "").strip().lower()
        allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS") or ""

        print("[authlogout] COOKIE_DOMAIN_BASE:", cookie_domain_base)
        print("[authlogout] COGNITO_DOMAIN:", cognito_domain)
        print("[authlogout] COGNITO_CLIENT_ID present:", bool(client_id), "len:", len(client_id))
        print("[authlogout] SITE_HOST:", site_host_fallback)
        print("[authlogout] ALLOWED_HOSTS raw:", allowed_hosts_raw)

        if not cognito_domain or not client_id or not site_host_fallback:
            print("[authlogout] MISCONFIG: required env var(s) missing")
            return {
                "statusCode": 500,
                "headers": {"Cache-Control": "no-store"},
                "body": "Server misconfiguration",
            }

        allowed_hosts = set(
            h.strip().lower()
            for h in allowed_hosts_raw.split(",")
            if h.strip()
        )
        print("[authlogout] allowed_hosts parsed:", sorted(list(allowed_hosts)))

        # Host selection
        state_host = (qs.get("state") or "").strip().lower()
        print("[authlogout] state_host:", state_host)

        if state_host and state_host in allowed_hosts:
            viewer_host = state_host
            print("[authlogout] viewer_host from state:", viewer_host)
        else:
            viewer_host = site_host_fallback
            print("[authlogout] viewer_host fallback SITE_HOST:", viewer_host)

        # Canonicalise host (Option A: no www sessions)
        if viewer_host.startswith("www."):
            print("[authlogout] canonicalising host (strip www)")
            viewer_host = viewer_host[4:]

        print("[authlogout] final viewer_host:", viewer_host)

        # Cookie expiry rules
        domain_attr = ""
        if cookie_domain_base and cookie_domain_base == viewer_host:
            domain_attr = "; Domain=" + cookie_domain_base
        print("[authlogout] cookie domain_attr:", domain_attr)

        cookies = [
            _expire_cookie("CloudFront-Policy", domain_attr, http_only=True),
            _expire_cookie("CloudFront-Signature", domain_attr, http_only=True),
            _expire_cookie("CloudFront-Key-Pair-Id", domain_attr, http_only=True),
            _expire_cookie("ml_user", domain_attr, http_only=False),
        ]

        print("[authlogout] cookies to expire:", [c.split("=", 1)[0] for c in cookies])

        # Cognito logout redirect
        return_to = f"https://{viewer_host}/logged-out.html"
        encoded_return_to = urllib.parse.quote(return_to, safe="")

        logout_url = (
            f"https://{cognito_domain}/logout"
            f"?client_id={client_id}"
            f"&logout_uri={encoded_return_to}"
        )

        print("[authlogout] return_to:", return_to)
        print("[authlogout] logout_url:", logout_url)
        print(f"[authlogout] END rid={rid}")

        return {
            "statusCode": 302,
            "headers": {
                "Location": logout_url,
                "Cache-Control": "no-store",
            },
            "multiValueHeaders": {
                "Set-Cookie": cookies
            },
            "body": ""
        }

    except Exception as e:
        import traceback
        print("[authlogout] EXCEPTION:", repr(e))
        print(traceback.format_exc())
        return {
            "statusCode": 500,
            "headers": {"Cache-Control": "no-store"},
            "body": "Logout error",
        }

"""

    login_lambda = aws.lambda_.Function(
        "authLoginFn",
        role=lambda_role.arn,
        runtime="python3.11",
        handler="index.handler",
        name=f"{name_prefix}-auth-login",
        timeout=5,
        code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(login_lambda_code)}),
        environment=aws.lambda_.FunctionEnvironmentArgs(
            variables={
                "COGNITO_DOMAIN": cognito_auth_domain,
                "COGNITO_CLIENT_ID": user_pool_client.id,
                "REDIRECT_PATH": redirect_path,
                "STATE_SECRET": state_secret,
                "ALLOWED_HOSTS": allowed_hosts_csv,
                "SITE_HOST": aliases[0],
                "ORIGIN_VERIFY_SECRET": origin_verify_secret,
            }
        ),
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )
    pulumi.export("authLoginFnName", login_lambda.name)

    callback_lambda = aws.lambda_.Function(
        "authCallbackFn",
        role=lambda_role.arn,
        runtime="python3.11",
        handler="index.handler",
        name=f"{name_prefix}-auth-callback",
        timeout=15,
        code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(callback_lambda_code)}),
        environment=aws.lambda_.FunctionEnvironmentArgs(
            variables={
                "COGNITO_DOMAIN": cognito_auth_domain,
                "COGNITO_CLIENT_ID": user_pool_client.id,
                "COGNITO_CLIENT_SECRET": user_pool_client.client_secret,
                "REDIRECT_PATH": redirect_path,
                "POST_LOGIN_PATH": post_login_path,
                "SITE_HOST": aliases[0],
                "CF_KEY_PAIR_ID": cloudfront_key_pair_id,
                "CF_PRIVATE_KEY_PEM": cloudfront_private_key_pem,
                "COOKIE_TTL_SECONDS": str(cookie_ttl_seconds),
                **({"COOKIE_DOMAIN_BASE": cookie_domain_base} if cookie_domain_base else {}),
                "ALLOWED_HOSTS": allowed_hosts_csv,
                "STATE_SECRET": state_secret,
                "ORIGIN_VERIFY_SECRET": origin_verify_secret,
            }
        ),
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )
    pulumi.export("authCallbackFnName", callback_lambda.name)

    logout_lambda = aws.lambda_.Function(
        "authLogoutFn",
        role=lambda_role.arn,
        runtime="python3.11",
        handler="index.handler",
        name=f"{name_prefix}-auth-logout",
        timeout=5,
        environment=aws.lambda_.FunctionEnvironmentArgs(
            variables={
                **({"COOKIE_DOMAIN_BASE": cookie_domain_base} if cookie_domain_base else {}),
                "COGNITO_DOMAIN": cognito_auth_domain,
                "COGNITO_CLIENT_ID": user_pool_client.id,
                "SITE_HOST": aliases[0],
                "ALLOWED_HOSTS": allowed_hosts_csv,
                "ORIGIN_VERIFY_SECRET": origin_verify_secret,
            }
        ),
        code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(logout_lambda_code)}),
        opts=pulumi.ResourceOptions(provider=callback_provider),
    )
    pulumi.export("authLogoutFnName", logout_lambda.name)
    
    # CloudWatch Log Groups (managed) - Lambda
    aws.cloudwatch.LogGroup(
        "authLoginLogGroup",
        name=f"/aws/lambda/{name_prefix}-auth-login",
        retention_in_days=log_retention_days,
        opts=pulumi.ResourceOptions(
            provider=callback_provider,
        ),
    )

    aws.cloudwatch.LogGroup(
        "authCallbackLogGroup",
        name=f"/aws/lambda/{name_prefix}-auth-callback",
        retention_in_days=log_retention_days,
        opts=pulumi.ResourceOptions(
            provider=callback_provider,
        ),
    )

    aws.cloudwatch.LogGroup(
        "authLogoutLogGroup",
        name=f"/aws/lambda/{name_prefix}-auth-logout",
        retention_in_days=log_retention_days,
        opts=pulumi.ResourceOptions(
            provider=callback_provider,
        ),
    )



    return lambda_role, login_lambda, callback_lambda, logout_lambda, cookie_ttl_seconds
