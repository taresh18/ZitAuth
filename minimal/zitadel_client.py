import requests
from jose import jwt, jwk
from jose.utils import base64url_decode
import os
import json
import datetime
from urllib.parse import urlencode
from dotenv import load_dotenv
import logging
from typing import Optional
from utils import get_logger
from jose.exceptions import JWTClaimsError, JWTError

logger = get_logger("minimal.zitadel_client")

load_dotenv()

# Load from environment variables or a config file
ZITADEL_DOMAIN = os.getenv("ZITADEL_DOMAIN")
ZITADEL_CLIENT_ID = os.getenv("ZITADEL_CLIENT_ID")
ZITADEL_CLIENT_SECRET = os.getenv("ZITADEL_CLIENT_SECRET")
REDIRECT_URI = os.getenv("ZITADEL_REDIRECT_URI")

AUTH_ENDPOINT = os.getenv("ZITADEL_AUTHORIZATION_ENDPOINT")
TOKEN_ENDPOINT = os.getenv("ZITADEL_TOKEN_ENDPOINT")
JWKS_URL = os.getenv("ZITADEL_JWKS_URL")
USERINFO_URL = os.getenv("ZITADEL_USERINFO_URL")
SERVICE_ACCOUNT_FILE = os.getenv("SERVICE_ACCOUNT_FILE")
M2M_SCOPE = os.getenv("M2M_SCOPE")
API_PROJECT_ID = os.getenv("API_PROJECT_ID")
EXPECTED_AUDIENCE = os.getenv("EXPECTED_AUDIENCE")

# We can cache the JWKS to avoid fetching it on every validation
_jwks_cache = None

class ZitadelClient:
    def get_login_url(self) -> str:
        """Constructs the URL to redirect the user to for login."""
        params = {
            "client_id": ZITADEL_CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",  # zitadel suggest using code over implicit
            "scope": "openid email profile", # default scope as suggested in docs
            "prompt": "login", # Force login
        }
        url = f"{AUTH_ENDPOINT}?{urlencode(params)}"
        logger.info("Generated authorize URL")
        return url

    def exchange_code_for_tokens(self, code: str) -> dict:
        """Exchanges an authorization code for access and ID tokens."""
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        # Zitadel requires Basic Auth for the client credentials
        response = requests.post(
            TOKEN_ENDPOINT,
            data=payload,
            auth=(ZITADEL_CLIENT_ID, ZITADEL_CLIENT_SECRET)
        )
        response.raise_for_status()  # Raise an exception for bad responses
        data = response.json()
        logger.info(f"Exchanged code for tokens successfully, data received from Zitadel token endpoint: {data}")
        return data

    def get_userinfo(self, access_token: str) -> dict:
        """Fetch userinfo from ZITADEL using the access token."""
        resp = requests.get(
            USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        info = resp.json()
        logger.info(f"Fetched userinfo for sub={info.get('sub')}")
        return info

    def validate_token(
        self,
        token: str,
        verify_audience: bool = True,
        access_token: Optional[str] = None,
        expected_audience: Optional[str] = None,
    ) -> dict:
        """Validates a JWT token using ZITADEL's JWKS.

        - Uses the token header's `alg` to select the correct algorithm (ZITADEL can sign with RS*, ES*, or EdDSA).
        - Refreshes JWKS if the `kid` is not found (keys rotate).
        - Allows disabling audience verification for access tokens whose `aud` is not the client ID.
        """
        global _jwks_cache

        # Ensure JWKS is loaded (with timeout)
        if _jwks_cache is None:
            _jwks_cache = requests.get(JWKS_URL, timeout=10).json()

        logger.info("JWKS cache: %s", _jwks_cache)

        # Get header for kid and algorithm
        headers = jwt.get_unverified_headers(token)
        kid = headers.get('kid')
        alg = headers.get('alg')

        if not kid or not alg:
            raise ValueError("Token header missing required fields 'kid' or 'alg'")

        # Find JWK by kid; refresh once if not found
        def find_key(jwks, kid_value):
            return next((k for k in jwks.get('keys', []) if k.get('kid') == kid_value), None)

        key = find_key(_jwks_cache, kid)
        if not key:
            logger.info("Key with kid=%s not found in cache, refreshing JWKS", kid)
            _jwks_cache = requests.get(JWKS_URL, timeout=10).json()
            key = find_key(_jwks_cache, kid)
            if not key:
                raise ValueError("Public key not found in JWKS after refresh")

        # Build decode kwargs
        decode_kwargs = {
            'issuer': ZITADEL_DOMAIN,
            'algorithms': [alg],
        }
        # Audience handling:
        # - For API access tokens (expected_audience provided), disable audience verification in library
        #   and enforce it manually after verifying signature and issuer.
        # - For ID tokens (verify_audience True, expected_audience None), enforce client_id directly.
        if expected_audience:
            decode_kwargs['options'] = {"verify_aud": False}
        elif verify_audience:
            decode_kwargs['audience'] = ZITADEL_CLIENT_ID
        # If the ID token contains an at_hash claim, python-jose requires
        # the corresponding access_token to verify it. Pass it through when available.
        if access_token:
            decode_kwargs['access_token'] = access_token

        try:
            # Decode and validate
            decoded_token = jwt.decode(token, key, **decode_kwargs)
            # Manual audience enforcement for API tokens if needed
            if expected_audience:
                aud_claim = decoded_token.get('aud')
                aud_values = aud_claim if isinstance(aud_claim, list) else [aud_claim]
                aud_values = [a for a in aud_values if a]
                if not any(isinstance(a, str) and (a == expected_audience or a == f"{expected_audience}@portal" or expected_audience in a) for a in aud_values):
                    raise JWTClaimsError("Invalid audience after local verification")
            return decoded_token
        except (JWTClaimsError, JWTError) as e:
            # If audience mismatch, try a lenient path: verify signature + issuer only, then check aud manually
            if expected_audience:
                decode_kwargs_no_aud = {
                    'issuer': ZITADEL_DOMAIN,
                    'algorithms': [alg],
                    'options': {"verify_aud": False},
                }
                if access_token:
                    decode_kwargs_no_aud['access_token'] = access_token
                decoded_no_aud = jwt.decode(token, key, **decode_kwargs_no_aud)
                aud_claim = decoded_no_aud.get('aud')
                aud_values = aud_claim if isinstance(aud_claim, list) else [aud_claim]
                aud_values = [a for a in aud_values if a]
                logger.error("Audience mismatch. expected=%s token_aud=%s", expected_audience, aud_values)
                if any(isinstance(a, str) and (a == expected_audience or a == f"{expected_audience}@portal" or expected_audience in a) for a in aud_values):
                    return decoded_no_aud
            raise

    def get_expected_audience(self) -> Optional[str]:
        return EXPECTED_AUDIENCE

    def _load_service_account(self, path: Optional[str] = None) -> dict:
        """Load a ZITADEL service account JSON with fields: keyId, key, userId."""
        sa_path = path or SERVICE_ACCOUNT_FILE
        if not sa_path:
            # Default to a common filename in the project if env not set
            sa_path = os.path.join(os.path.dirname(__file__), "332768259986161667.json")
        if not os.path.isfile(sa_path):
            raise FileNotFoundError(f"Service account file not found at {sa_path}")
        with open(sa_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        required = ["keyId", "key", "userId"]
        for field in required:
            if field not in data or not data[field]:
                raise ValueError(f"Service account JSON missing required field: {field}")
        return data

    def get_m2m_token(self, scope: Optional[str] = None) -> dict:
        """Obtain an access token using JWT bearer grant with a ZITADEL service account.

        - Generates a client assertion JWT signed with the service account private key
        - Requests a token with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
        - Scope must include 'openid' and typically the project audience scope
        """
        service_account = self._load_service_account()

        # Claims per ZITADEL docs: iss=sub=service user id, aud=custom domain, short-lived
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "iss": service_account["userId"],
            "sub": service_account["userId"],
            "aud": ZITADEL_DOMAIN,
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(minutes=15)).timestamp()),
        }
        headers = {
            "alg": "RS256",
            "kid": service_account["keyId"],
        }

        assertion_jwt = jwt.encode(
            payload,
            service_account["key"],
            algorithm="RS256",
            headers=headers,
        )

        # Resolve and validate scope
        resolved_scope = (scope or M2M_SCOPE or "").strip()
        if not resolved_scope:
            # Try to construct from API_PROJECT_ID if available
            if API_PROJECT_ID:
                resolved_scope = f"urn:zitadel:iam:org:project:id:{API_PROJECT_ID}:aud"
            else:
                raise ValueError(
                    "Scope is required. Set M2M_SCOPE to include 'openid' and 'urn:zitadel:iam:org:project:id:{projectid}:aud', or set API_PROJECT_ID."
                )
        scopes = resolved_scope.split()
        if "openid" not in scopes:
            scopes.append("openid")
        # Ensure at least one :aud scope present for introspection compatibility
        has_aud_scope = any(s.startswith("urn:zitadel:iam:org:project:id:") and s.endswith(":aud") for s in scopes)
        if not has_aud_scope:
            if API_PROJECT_ID:
                scopes.append(f"urn:zitadel:iam:org:project:id:{API_PROJECT_ID}:aud")
            else:
                raise ValueError("Missing required ':aud' project scope. Add it to M2M_SCOPE or set API_PROJECT_ID.")
        resolved_scope = " ".join(scopes)

        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion_jwt,
            "scope": resolved_scope,
        }

        response = requests.post(
            TOKEN_ENDPOINT,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        if not response.ok:
            logger.error(
                "Service account JWT token request failed: status=%s body=%s",
                response.status_code,
                response.text,
            )
            response.raise_for_status()
        data = response.json()
        logger.info(f"Successfully fetched M2M access token via service account JWT: {data}")
        return data