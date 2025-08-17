# mobile app login flow
# 1. When an unauthenticated user visits your application,
# 2. you will create an authorization request to the authorization endpoint.
# 3. The Authorization Server (ZITADEL) will send an HTTP 302 to the user's browser, which will redirect them to the login UI.
# 4. The user will have to authenticate using the demanded auth mechanics.
# 5. Your application will be called on the registered callback path (redirect_uri) and be provided an authorization_code.
# 6. This authorization_code must then be sent together with you applications authentication (client_id + client_secret) to the token_endpoint
# 7. In exchange the Authorization Server (ZITADEL) will return an access_token and if requested a refresh_token and in the case of OIDC an id_token as well
# 8. The access_token can then be used to call a Resource Server (API). The token will be sent as Authorization Header.

# Machine 2 Machine (M2M) flow:
# 1. Create the service account in zitadel and generate a public/private key pair. public keys is stored in zitadel and we download the private key from zitadel console.
# 2. Crate a JWT with the service account details signed by the private key and send the JWT to the ZITADEL token endpoint to get the access token
# 3. Use this access token for validation using the JWKS

# ztadel recommends using PKCE for user-agent / web clients and JWT for machine-to-machine (M2M) clients.

# references:
# mobile app login (PKCE): https://zitadel.com/docs/guides/integrate/login/oidc/login-users
# service account: https://zitadel.com/docs/guides/integrate/service-users/private-key-jwt
# apis: https://zitadel.com/docs/apis/openidoauth/endpoints

import requests
from jose import jwt
import os
import json
import datetime
from urllib.parse import urlencode
from dotenv import load_dotenv
from typing import Optional
from .utils import get_logger, get_key_from_jwks

logger = get_logger("zitauth.zitadel_client")

load_dotenv()

class ZitadelClient:
    def __init__(self):
        # read from environment variables
        try:
            self.zitadel_domain = os.environ["ZITADEL_DOMAIN"]
            self.zitadel_client_id = os.environ["ZITADEL_CLIENT_ID"]
            self.zitadel_redirect_url = os.environ["ZITADEL_REDIRECT_URL"]
            self.zitadel_auth_endpoint = os.environ["ZITADEL_AUTHORIZATION_ENDPOINT"]
            self.zitadel_token_endpoint = os.environ["ZITADEL_TOKEN_ENDPOINT"]
            self.zitadel_jwks_url = os.environ["ZITADEL_JWKS_URI"]
            self.zitadel_userinfo_url = os.environ["ZITADEL_USERINFO_ENDPOINT"]
            self.service_account_file = os.environ["SERVICE_ACCOUNT_FILE"]
        except KeyError as e:
            logger.error(f"Environment variable {e} is not set")
            raise e
        finally:
            logger.info("Environment variables configured successfully")
            logger.info(f"ZITADEL_DOMAIN: {self.zitadel_domain}")
            logger.info(f"ZITADEL_CLIENT_ID: {self.zitadel_client_id}")
            logger.info(f"ZITADEL_REDIRECT_URL: {self.zitadel_redirect_url}")
            logger.info(f"ZITADEL_AUTHORIZATION_ENDPOINT: {self.zitadel_auth_endpoint}")
            logger.info(f"ZITADEL_TOKEN_ENDPOINT: {self.zitadel_token_endpoint}")
            logger.info(f"ZITADEL_JWKS_URI: {self.zitadel_jwks_url}")
            logger.info(f"ZITADEL_USERINFO_ENDPOINT: {self.zitadel_userinfo_url}")
            logger.info(f"SERVICE_ACCOUNT_FILE: {self.service_account_file}")
            
        # cache the public keys obtained from zitadel JWKS endpoint for reuse
        self.jwks_cache = None

    def get_login_url(
        self,
        state: str,
        code_challenge: str,
    ) -> str:
        """Construct the URL to redirect the user to for login using the PKCE method"""
        params = {
            "client_id": self.zitadel_client_id, # It's the resource id of the application where you want your users to login.
            "redirect_uri": self.zitadel_redirect_url, # Must be one of the pre-configured redirect uris for your application.
            "response_type": "code",  # for PKCE
            "scope": "openid email profile", # Request additional information about the user with scopes. The claims will be returned on the userinfo_endpoint or in the token (when configured).
            "prompt": "login", # force login
            "state": state,
            # required for PKCE - You will have to generate a random string, hash it and send this hash on the authorization_endpoint
            # On the token_endpoint you will then send the plain string for the authorization to compute the hash as well and to verify it's correct
            "code_challenge": code_challenge,
            "code_challenge_method": "S256", # must always be S256
        }
        url = f"{self.zitadel_auth_endpoint}?{urlencode(params)}"
        logger.info(f"Generated authorize URL with PKCE: {url}")
        return url

    def exchange_code_for_token(self, code: str, code_verifier: str) -> dict:
        """Exchange authorization code for accesstoken"""
        logger.info(f"Exchanging code for tokens with code_verifier: {code_verifier}")
        # this will return the access token as JWT (configured to return a JWT from zitadel's console. default is opaque token which requires token introspection)
        payload = {
            "grant_type": "authorization_code", # must be authorization_code for PKCE
            "code": code, # the code that was issued from the authorization request
            "redirect_uri": self.zitadel_redirect_url, # callback uri where the code was sent to. Must match exactly the redirect_uri of the authorization request
            "client_id": self.zitadel_client_id, # the client id of the application
            # required for PKCE - send the plain string for the authorization to compute the hash as well and to verify it's correct    
            "code_verifier": code_verifier,
        }
        
        response = requests.post(
            self.zitadel_token_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=payload,
        )
        response.raise_for_status()
        data = response.json()
        logger.info(f"Exchanged code for tokens successfully")
        return data

    def load_service_account_file(self) -> dict:
        """Load a ZITADEL service account JSON file"""
        if not os.path.isfile(self.service_account_file):
            raise FileNotFoundError(f"Service account file not found at {self.service_account_file}")
        with open(self.service_account_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def get_m2m_token(self) -> dict:
        """Obtain an access token using the jwt generated from a ZITADEL service account"""

        # Load the service account details from the private key file already generated via zitadel service account
        service_account = self.load_service_account_file()

        # Geneate the JWT with the information from the private key
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "iss": service_account["userId"], # represents the requesting party (owner of the private key) - should be the same as userId from the downloaded JSON
            "sub": service_account["userId"], # represents the application - should be the same as userId from the downloaded JSON
            "aud": self.zitadel_domain, # zitadel domain
            "iat": int(now.timestamp()), # is a unix timestamp of the creation signing time of the JWT, e.g. now and must not be older than 1 hour ago
            "exp": int((now + datetime.timedelta(minutes=15)).timestamp()), # is the unix timestamp of expiry of this assertion
        }
        headers = {
            "alg": "RS256", # fixed
            "kid": service_account["keyId"], # keyId from the private key JSON
        }

        # Sign the JWT using RS256 algorithm
        encoded_jwt = jwt.encode(
            payload,
            service_account["key"],
            algorithm="RS256",
            headers=headers,
        )

        logger.info(f"Generated Encoded JWT: {encoded_jwt}")

        # Request an OAuth token with the generated JWT
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", # should be set to urn:ietf:params:oauth:grant-type:jwt-bearer
            "scope": "openid", # scope should contain any Scopes you want to include, but must include openid, can include email, profile, etc.
            "assertion": encoded_jwt, # the encoded JWT we generated
        }

        # POST request to the zitadel token endpoint
        response = requests.post(
            self.zitadel_token_endpoint,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        data = response.json()
        logger.info(f"Successfully fetched M2M access token via service account JWT: {data}")
        return data

    def validate_token(
        self,
        token: str,
    ) -> dict:
        """Validates a JWT token using ZITADEL's JWKS.

        - Uses the token header's `alg` to select the correct algorithm (ZITADEL can sign with RS*, ES*, or EdDSA).
        - Refreshes JWKS if the `kid` is not found (keys rotate).
        - Allows disabling audience verification for access tokens whose `aud` is not the client ID.
        """

        # load zitadel's public keys
        if self.jwks_cache is None:
            self.jwks_cache = requests.get(self.zitadel_jwks_url, timeout=10).json()

        # extract kid and alg from the token header
        headers = jwt.get_unverified_headers(token)
        kid = headers.get('kid')
        alg = headers.get('alg') # must be RS256 if generated by zitadel

        if not kid or not alg or alg not in ["RS256"]:
            raise ValueError("Token header missing required fields 'kid' or 'alg'")
        
        # get the key from  zitadel's jwks, refresh once if not found
        key = get_key_from_jwks(self.jwks_cache, kid)
        if not key:
            self.jwks_cache = requests.get(self.zitadel_jwks_url, timeout=10).json()
            key = get_key_from_jwks(self.jwks_cache, kid)
            if not key:
                raise ValueError("Public key not found in JWKS after refresh")

        # build decode kwargs for jwt.decode
        decode_kwargs = {
            'issuer': self.zitadel_domain,
            'algorithms': [alg],
            'options': {"verify_aud": False},
        }

        decoded_token = jwt.decode(token, key, **decode_kwargs)    
        return decoded_token

    def get_userinfo(self, access_token: str) -> dict:
        """Fetch userinfo from zitadel using the access token"""
        logger.info(f"Fetching userinfo for access_token")
        # Send the access_token of the user as Bearer Token in the authorization header
        resp = requests.get(
            self.zitadel_userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        info = resp.json()
        return info