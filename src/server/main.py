# versiondiff-sentinel/src/server/main.py
import asyncio
import logging
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.server.api import router as api_router
from src.server.simulation import SIMULATION_STATE

logger = logging.getLogger("uvicorn.error")

app = FastAPI(title="VersionDiff Sentinel API")

# CORS (allow the frontend dev server origin if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# mount API router
app.include_router(api_router, prefix="")

# Mount the reports directory as a static files endpoint.
# This makes direct GET requests to /reports/.../deep_analysis.json or /reports/.../full_report.html work.
REPORTS_DIR = os.environ.get("REPORTS_DIR", "/app/reports")
if os.path.isdir(REPORTS_DIR):
    app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")
else:
    # still mount (StaticFiles will error on missing directory at runtime),
    # but log a message so devs notice
    logger.warning(f"REPORTS_DIR {REPORTS_DIR} does not exist at startup; attempting mount anyway")
    app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")


# A simple health endpoint
@app.get("/healthz")
async def healthz():
    return {"status": "ok", "sim": SIMULATION_STATE.get("status")}

# WebSocket handling etc. (if you already have logic, keep it).
# If your original main.py had WebSocket logic, keep it; above we only added mounting and kept the rest.
