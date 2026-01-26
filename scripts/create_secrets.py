#!/usr/bin/env python3
"""
create_secrets.py

Run from repo subfolder: /scripts

Creates per-environment secrets JSON files under /secrets and generates
CloudFront RSA keypairs (public + private PEM) for staging and prod.

You can pass either:
  --domain example.com
or:
  --site example-com

If --domain is provided, the script derives a slug like:
  example.com     -> example-com
  example.co.uk   -> example-co-uk
  foo.bar.dev     -> foo-bar-dev

Outputs (per env):
  secrets/<slug>-<env>.secrets.json
  secrets/<slug>-<env>-private-key.pem
  secrets/<slug>-<env>-public-key.pem
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import secrets as py_secrets
import sys
from typing import Tuple, Optional


def repo_root_from_scripts_dir() -> Path:
    # <repo>/scripts/create_secrets.py -> <repo>
    return Path(__file__).resolve().parents[1]


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_write_text(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"Refusing to overwrite existing file: {path} (use --force)")
    path.write_text(content, encoding="utf-8", newline="\n")


def generate_random_secret(length_bytes: int = 32) -> str:
    return py_secrets.token_urlsafe(length_bytes)


def _clean_domain(domain: str) -> str:
    d = domain.strip().lower()

    # Remove scheme
    d = re.sub(r"^https?://", "", d)

    # Remove path/query/fragment
    d = re.split(r"[/?#]", d, maxsplit=1)[0]

    # Remove port if present
    d = re.sub(r":\d+$", "", d)

    # Remove leading wildcard
    if d.startswith("*."):
        d = d[2:]

    # Remove trailing dot
    d = d.rstrip(".")

    return d


def domain_to_slug(domain: str) -> str:
    """
    Converts a domain name to a slug suitable for stack/file naming.

    Examples:
      example.com       -> example-com
      example.co.uk     -> example-co-uk
      my.site.io        -> my-site-io
      *.foo.bar.co.uk   -> foo-bar-co-uk

    Keeps all labels (including multi-part TLDs like co.uk) by simply replacing dots with hyphens.
    """
    d = _clean_domain(domain)
    if not d or "." not in d:
        raise ValueError(f"Domain does not look valid: '{domain}'")

    # Replace any character that isn't alnum, dot, or hyphen with hyphen
    d = re.sub(r"[^a-z0-9.\-]+", "-", d)

    # Collapse multiple dots/hyphens
    d = re.sub(r"\.+", ".", d)
    d = re.sub(r"-{2,}", "-", d)

    # Convert dots to hyphens
    slug = d.replace(".", "-")

    # Trim stray hyphens
    slug = slug.strip("-")

    if not slug:
        raise ValueError(f"Could not derive a slug from domain: '{domain}'")

    return slug


def generate_rsa_keypair_pem(key_size: int = 2048) -> Tuple[str, str]:
    """
    Returns (private_pem, public_pem) as strings.

    Prefers 'cryptography'. If unavailable, tries OpenSSL.
    """
    # 1) Try cryptography
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return private_pem, public_pem
    except ModuleNotFoundError:
        pass
    except Exception as e:
        raise RuntimeError(f"Failed generating RSA keys using 'cryptography': {e}") from e

    # 2) Fallback to openssl if installed
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        priv_path = tmp / "private.pem"
        pub_path = tmp / "public.pem"

        try:
            subprocess.run(
                ["openssl", "genrsa", "-out", str(priv_path), str(key_size)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["openssl", "rsa", "-in", str(priv_path), "-pubout", "-out", str(pub_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            private_pem = priv_path.read_text(encoding="utf-8")
            public_pem = pub_path.read_text(encoding="utf-8")
            return private_pem, public_pem
        except FileNotFoundError as e:
            raise RuntimeError(
                "Neither 'cryptography' nor 'openssl' is available.\n\n"
                "Install one of:\n"
                "  - pip install cryptography\n"
                "  - Install OpenSSL and ensure 'openssl' is on PATH\n"
            ) from e
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"OpenSSL failed:\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}") from e


def write_env_secrets(
    secrets_dir: Path,
    slug: str,
    env_name: str,
    force: bool,
    key_size: int,
) -> None:
    priv_pem_path = secrets_dir / f"{slug}-{env_name}-private-key.pem"
    pub_pem_path = secrets_dir / f"{slug}-{env_name}-public-key.pem"
    json_path = secrets_dir / f"{slug}-{env_name}.secrets.json"

    private_pem, public_pem = generate_rsa_keypair_pem(key_size=key_size)

    safe_write_text(priv_pem_path, private_pem, force=force)
    safe_write_text(pub_pem_path, public_pem, force=force)

    payload = {
        "env": env_name,
        "slug": slug,
        "stateSecret": generate_random_secret(32),
        "originVerifySecret": generate_random_secret(32),
        "cloudfrontPrivateKeyPem": private_pem,
        # Convenience fields (non-secret, but useful):
        "cloudfrontPrivateKeyPemPath": str(priv_pem_path.as_posix()),
        "cloudfrontPublicKeyPemPath": str(pub_pem_path.as_posix()),
    }

    safe_write_text(json_path, json.dumps(payload, indent=2) + "\n", force=force)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate per-env secrets + CloudFront keypairs.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="Domain name, e.g. example.com or example.co.uk")
    group.add_argument("--site", help="Pre-made slug, e.g. example-com")

    parser.add_argument(
        "--envs",
        default="staging,prod",
        help="Comma-separated env list (default: staging,prod)",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        help="RSA key size for CloudFront keypair (default: 2048)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing files",
    )

    args = parser.parse_args()

    slug: Optional[str] = None
    if args.domain:
        slug = domain_to_slug(args.domain)
    else:
        slug = args.site.strip().lower().strip("-")

    envs = [e.strip() for e in args.envs.split(",") if e.strip()]
    if not envs:
        print("No envs specified.", file=sys.stderr)
        return 2

    repo_root = repo_root_from_scripts_dir()
    secrets_dir = repo_root / "secrets"
    ensure_dir(secrets_dir)

    created = []
    for env in envs:
        write_env_secrets(
            secrets_dir=secrets_dir,
            slug=slug,
            env_name=env,
            force=args.force,
            key_size=args.key_size,
        )
        created.append(env)

    print(f"Slug: {slug}")
    print("Secrets generated:")
    for env in created:
        print(f"  - secrets/{slug}-{env}.secrets.json")
        print(f"  - secrets/{slug}-{env}-private-key.pem")
        print(f"  - secrets/{slug}-{env}-public-key.pem")

    print("\nReminder: ensure 'secrets/' is in .gitignore so these never get committed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
