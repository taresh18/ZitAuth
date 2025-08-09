import requests
from jose import jwt, jwk
from jose.utils import base64url_decode
import os
from urllib.parse import urlencode
from dotenv import load_dotenv
import logging
from utils import get_logger

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

# We can cache the JWKS to avoid fetching it on every validation
_jwks_cache = None

class ZitadelClient:
    def get_login_url(self) -> str:
        """Constructs the URL to redirect the user to for login."""
        params = {
            "client_id": ZITADEL_CLIENT_ID,
            "response_type": "code",
            "scope": "openid email profile", # Requesting an ID Token and user info
            "redirect_uri": REDIRECT_URI,
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
        logger.info("Exchanged code for tokens successfully")
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
        logger.info("Fetched userinfo for sub=%s", info.get("sub"))
        return info

    def validate_token(self, token: str) -> dict:
        """Validates a JWT token using Zitadel's public keys (JWKS)."""
        global _jwks_cache
        if _jwks_cache is None:
            _jwks_cache = requests.get(JWKS_URL).json()

        logger.info("JWKS cache: %s", _jwks_cache)

        # Get the key ID from the token header
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']

        # Find the key in the JWKS that matches the kid
        key = next((k for k in _jwks_cache['keys'] if k['kid'] == kid), None)
        if not key:
            raise ValueError("Public key not found in JWKS")

        # Decode and validate the token
        decoded_token = jwt.decode(
            token,
            key,
            algorithms=['RS256'],
            audience=ZITADEL_CLIENT_ID, # The token must be intended for our app
            issuer=ZITADEL_DOMAIN # The token must be from Zitadel
        )
        return decoded_token