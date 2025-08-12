import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from typing import Dict

from .client import ZitadelClient
from .utils import get_logger, generate_state, generate_code_verifier, generate_code_challenge

app = FastAPI(title="ZitAuth: Zitadel Auth Wrapper")
client = ZitadelClient()

logger = get_logger("zitauth.app")

# origin of the SPA - will be used to redirect the user after login
SPA_ORIGIN = os.environ["SPA_ORIGIN"]
# cache the PKCE code_verifier with state for reuse on the callback
PKCE_CACHE: Dict[str, str] = {}

@app.get("/api/v1/login")
async def login(request: Request):
    """
    Redirects the user to ZITADEL login page.
    """
    try:
        logger.info(f"Request received for login")
        # generate state, code_verifier and code_challenge for PKCE
        state = generate_state()
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        logger.info(f"state: {state}, code_verifier: {code_verifier}, code_challenge: {code_challenge}")
        # store the state and code_verifier in cache
        PKCE_CACHE[state] = code_verifier

        # construct the login url
        login_url = client.get_login_url(
            state=state,
            code_challenge=code_challenge,
        )
        # redirect to ZITADEL login page
        return RedirectResponse(url=login_url)
    except Exception as e:
        logger.error(f"GET /login failed", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Could not log in. Error: {e}")

@app.get("/api/v1/callback")
async def auth_callback(_: Request, code: str, state: str):
    """
    Callback from ZITADEL after successful login. exchange access token with the code received from ZITADEL

    args: 
    - code - the code received from ZITADEL
    - state - the state received from ZITADEL

    returns: 
    - redirect to the SPA origin with the access token in the URL fragment
    """
    try:
        logger.info(f"Call back hit after user login, received code from Zitadel")
        # retrieve and consume code_verifier from cache
        code_verifier = PKCE_CACHE.pop(state, None)
        if not code_verifier:
            raise HTTPException(status_code=400, detail="Invalid or expired state")

        # exchange the code for access token
        tokens = client.exchange_code_for_token(code, code_verifier=code_verifier)
        access_token = tokens.get("access_token")
        logger.info(f"User logged in successfully; returning access token to SPA via redirect")

    except Exception as e:
        logger.error(f"Login failed during callback processing", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Could not log in. Error: {e}")

    # redirect the browser back to the SPA origin with the access token in the URL fragment
    fragment = f"#access_token={access_token}" if access_token else ""
    return RedirectResponse(url=f"{SPA_ORIGIN}/{fragment}")

@app.get("/api/v1/m2m-token")
async def get_m2m_token():
    """
    Issue a machine-to-machine access token using the service account.

    returns: access token received from Zitadel token endpoint.
    """
    logger.info(f"Request received for m2m token")
    try:
        data = client.get_m2m_token()
        return {"access_token": data["access_token"]}
    except Exception as e:
        logger.error(f"GET /auth/m2m-token failed", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get M2M token: {e}")

@app.get("/api/v1/validate")
async def validate_token(request: Request):
    """
    Validate a token for authentication

    returns: authentication status
    """
    logger.info(f"Request received for validate")
    # get the token from the authorization header
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        logger.error("Missing bearer token in authorization header")
        raise HTTPException(status_code=400, detail="Missing bearer token")

    token = auth_header.split(" ", 1)[1].strip()
    status = client.validate_token(token)
    return status


@app.get("/api/v1/userinfo")
async def get_userinfo(request: Request):
    """
    Fetch user info from Zitadel using the provided access token.

    Accepts Authorization: Bearer <access_token> and returns data under {"userinfo": ...}
    """
    logger.info(f"Request received for userinfo")
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        logger.error("Missing bearer token in authorization header")
        raise HTTPException(status_code=400, detail="Missing bearer token")

    # get the access token from the authorization header
    token = auth_header.split(" ", 1)[1].strip()

    try:
        # fetch userinfo from Zitadel using the access token
        info = client.get_userinfo(token)
        return {"userinfo": info}
    except Exception as e: 
        logger.error(f"GET /auth/userinfo failed", exc_info=True)
        raise HTTPException(status_code=401, detail=f"Failed to fetch userinfo. Error: {e}")