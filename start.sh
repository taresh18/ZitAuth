# run the zitdadel server
docker compose up -d

# run the zitauth service
uvicorn python.main:app --reload --port 8000

# run the spa app (mobile login flow)
uvicorn examples.spa_app.main:app --reload --port 8001

# run the m2m sim (local to cloud service simulation using service account JWT)
python examples/m2m_sim.py