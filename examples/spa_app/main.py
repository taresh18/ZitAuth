import os
import sys
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from python.utils import get_logger

logger = get_logger("examples.spa_app")

ZITAUTH_BASE_URL = "http://localhost:8000"

app = FastAPI()
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir, html=True), name="static")

@app.get("/")
async def index():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/api/login")
async def login_start():
    """Redirect the browser to zitauth /api/v1/login to start OIDC login."""
    logger.info("redirecting to zitauth /api/v1/login to start OIDC login")
    return RedirectResponse(url=f"{ZITAUTH_BASE_URL}/api/v1/login")

@app.get("/api/protected")
async def protected(request: Request):
    """
    Protected endpoint

    - Accepts Authorization: Bearer <token>
    - Delegates validation to ZitAuth's GET /api/v1/validate
    """
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    try:
        resp = requests.get(
            f"{ZITAUTH_BASE_URL}/api/v1/validate",
            headers={"Authorization": auth_header},
            timeout=10,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        logger.info(f"Successfully validated token")
        return {"authenticated": True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Validation call failed: {exc}")

@app.get("/api/userinfo")
async def userinfo(request: Request):
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    try:
        resp = requests.get(
            f"{ZITAUTH_BASE_URL}/api/v1/userinfo",
            headers={"Authorization": auth_header},
            timeout=10,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        logger.info(f"Successfully fetched userinfo: {resp.json()}")
        return resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Userinfo call failed: {exc}")
