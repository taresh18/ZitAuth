# main.py
import os
import logging
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from zitadel_client import ZitadelClient
from utils import get_logger

app = FastAPI()
client = ZitadelClient()

logger = get_logger("minimal.app")

# WARNING: In a real app, use a more secure secret and session storage.
app.add_middleware(SessionMiddleware, secret_key="a_very_secret_key")

@app.get("/")
async def root(request: Request):
    """Home page with user info if logged in, otherwise a login link."""
    user = request.session.get("user")
    if user:
        return JSONResponse({
            "message": "Welcome! you are already logged in",
            "user_info": user,
            "logout_link": "/logout",
            "profile_link": "/api/profile"
        })
    return JSONResponse({
        "message": "You are not logged in.",
        "login_link": "/login"
    })

@app.get("/login")
async def login():
    """Redirects the user to the Zitadel login page."""
    logger.info("Redirecting user to ZITADEL authorization endpoint")
    login_url = client.get_login_url()
    logger.info(f"login_url: {login_url}")
    return RedirectResponse(url=login_url)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str):
    """
    Handles the redirect from Zitadel after successful login.
    Exchanges the code for tokens and stores user info in the session.
    """
    try:
        logger.info(f"Call back hit after user login, received code from Zitadel: {code}")
        tokens = client.exchange_code_for_tokens(code)
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")

        # At this minimal stage: use userinfo endpoint to fetch profile
        # This avoids at_hash validation issues when not explicitly verifying ID tokens
        user_info = client.get_userinfo(access_token)

        # Store essential info in the session
        request.session["user"] = {
            "sub": user_info.get("sub"),
            "name": user_info.get("name"),
            "email": user_info.get("email"),
        }
        # Also store the tokens to use for protected APIs
        request.session["access_token"] = access_token
        request.session["id_token"] = id_token
        logger.info("User logged in successfully")
        logger.info(f"user_info: {user_info}")
        logger.info(f"access_token: {access_token}")
        logger.info(f"id_token: {id_token}")

    except Exception as e:
        logger.exception("Login failed during callback processing")
        raise HTTPException(status_code=400, detail=f"Could not log in. Error: {e}")

    return RedirectResponse(url="/api/profile")

@app.get("/api/profile")
async def get_profile(request: Request):
    """A protected endpoint that requires a valid access token."""
    logger.info("Profile endpoint requested")
    # Prefer Authorization header for M2M/service-to-service calls
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    header_bearer_token = None
    if auth_header and auth_header.lower().startswith("bearer "):
        header_bearer_token = auth_header.split(" ", 1)[1].strip()

    access_token = header_bearer_token or request.session.get("access_token")
    id_token = None if header_bearer_token else request.session.get("id_token")
    if not access_token and not id_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # If header bearer token is present, prefer local JWT validation (fast, no round-trip)
        if header_bearer_token and access_token and access_token.count(".") == 2:
            # Enforce expected audience if provided; allow lenient match for variations like '<id>@portal'
            expected_aud = client.get_expected_audience()
            claims = client.validate_token(
                access_token,
                verify_audience=bool(expected_aud),
                expected_audience=expected_aud,
            )
        elif header_bearer_token:
            # Opaque tokens are not supported without introspection; reject
            raise HTTPException(status_code=401, detail="Opaque access tokens are not accepted; use JWTs")
        else:
            # Browser/session flow: validate via JWKS. Prefer ID token, fallback to access token if JWT
            if id_token:
                claims = client.validate_token(id_token, verify_audience=True, access_token=access_token)
            elif access_token and access_token.count(".") == 2:
                # Access tokens often have audience of APIs, not this client. Skip audience verification.
                claims = client.validate_token(access_token, verify_audience=False)
            else:
                raise HTTPException(status_code=400, detail="No JWT token available for validation")

        logger.info("Token validated successfully sub=%s", claims.get("sub"))
        return {"message": "This is a protected endpoint.", "claims": claims}
    except Exception as e:
        logger.exception("Failed to retrieve profile")
        raise HTTPException(status_code=401, detail=f"Invalid token. Error: {e}")

@app.get("/logout")
async def logout(request: Request):
    """Clears the session to log the user out."""
    request.session.clear()
    logger.info("User session cleared; logged out")
    return RedirectResponse(url="/")