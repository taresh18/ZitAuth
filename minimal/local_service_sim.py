# local_service_sim.py

import os
import requests
from dotenv import load_dotenv
from zitadel_client import ZitadelClient
from utils import get_logger

# Load environment variables from .env
load_dotenv()

logger = get_logger("minimal.local_service")

# The "Cloud Service" endpoint we want to call
CLOUD_API_ENDPOINT = "http://localhost:8000/api/profile"


def main():
    """
    Simulates a local service authenticating itself and calling a protected
    cloud API using a ZITADEL service account (JWT bearer grant).
    """
    logger.info("--- Starting Local to Cloud Service Simulation (Service Account JWT) ---")

    zitadel_auth = ZitadelClient()

    try:
        # Fetch M2M token using service account assertion
        logger.info("Requesting M2M access token via service account JWT...")
        token_data = zitadel_auth.get_m2m_token()
        access_token = token_data.get("access_token")

        if not access_token:
            logger.error("Failed to get access token via service account JWT.")
            return

        logger.info(f"Successfully obtained M2M access token: {access_token[:30]}...")

        # Call the protected cloud service API
        logger.info(f"Calling protected cloud API at {CLOUD_API_ENDPOINT}")
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = requests.get(CLOUD_API_ENDPOINT, headers=headers, timeout=10)
        response.raise_for_status()

        api_data = response.json()
        logger.info("--- Successfully called the Cloud API! ---")
        logger.info("Response from cloud service:")
        logger.info(api_data)

    except Exception:
        logger.exception("Simulation failed.")


if __name__ == "__main__":
    main()