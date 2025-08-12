import os
import sys
import requests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from python.utils import get_logger
logger = get_logger("examples.m2m_sim")

PROTECTED_API_ENDPOINT = "http://localhost:3001/api/protected"
# ZitAuth endpoint to obtain an M2M token via service account
ZITAUTH_M2M_TOKEN_ENDPOINT = "http://localhost:8000/api/v1/m2m-token"


def main():
    """
    Simulates a local service authenticating itself and calling a protected
    cloud API using a ZITADEL service account (JWT bearer grant).
    """
    logger.info("Starting Local to Cloud Service Simulation")

    try:
        # Always fetch M2M token from the ZitAuth endpoint (service account JWT grant handled server-side)
        logger.info("Requesting M2M access token from ZitAuth endpoint...")
        resp = requests.get(ZITAUTH_M2M_TOKEN_ENDPOINT, timeout=10)
        resp.raise_for_status()
        token_data = resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            logger.error("ZitAuth did not return an access_token field.")
            return

        logger.info(f"Successfully obtained M2M access token: {access_token[:30]}...")

        # Call the protected cloud service API
        logger.info(f"Calling protected endpoint at {PROTECTED_API_ENDPOINT}")
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(PROTECTED_API_ENDPOINT, headers=headers, timeout=10)
        response.raise_for_status()

        api_data = response.json()
        logger.info("Successfully accessed the protected API!")
        logger.info("Response from cloud service:")
        logger.info(api_data)

    except Exception:
        logger.exception("Simulation failed.")


if __name__ == "__main__":
    main()