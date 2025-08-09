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
            "message": "Welcome!",
            "user_info": user,
            "logout_link": "/logout"
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
    return RedirectResponse(url=login_url)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str):
    """
    Handles the redirect from Zitadel after successful login.
    Exchanges the code for tokens and stores user info in the session.
    """
    try:
        logger.info("Handling auth callback; exchanging code for tokens")
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
        # Also store the access token to use for protected APIs
        request.session["access_token"] = access_token
        logger.info("User logged in successfully sub=%s email=%s", user_info.get("sub"), user_info.get("email"))

    except Exception as e:
        logger.exception("Login failed during callback processing")
        raise HTTPException(status_code=400, detail=f"Could not log in. Error: {e}")

    return RedirectResponse(url="/api/profile")

@app.get("/api/profile")
async def get_profile(request: Request):
    """A protected endpoint that requires a valid access token."""
    logger.info("Profile endpoint requested")
    access_token = request.session.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Minimal: just return userinfo fetched via access token
        userinfo = client.get_userinfo(access_token)
        logger.info("Profile retrieved successfully sub=%s", userinfo.get("sub"))
        return {"message": "This is a protected endpoint.", "userinfo": userinfo}
    except Exception as e:
        logger.exception("Failed to retrieve profile")
        raise HTTPException(status_code=401, detail=f"Invalid token. Error: {e}")

@app.get("/logout")
async def logout(request: Request):
    """Clears the session to log the user out."""
    request.session.clear()
    logger.info("User session cleared; logged out")
    return RedirectResponse(url="/")