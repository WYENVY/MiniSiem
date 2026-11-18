import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse

from siem import db

STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: Optional[str] = None) -> FastAPI:
    db_path = db_path or os.environ.get("SIEM_DB", db.DEFAULT_DB)
    db.init_db(db_path)
    app = FastAPI(title="Mini SIEM")

    @app.get("/api/summary")
    def summary():
        return db.summary(db_path)

    @app.get("/api/alerts")
    def alerts(limit: int = Query(100, ge=1, le=1000)):
        return db.get_alerts(db_path, limit)

    @app.get("/api/top-attackers")
    def top_attackers(limit: int = Query(10, ge=1, le=100)):
        return db.top_attackers(db_path, limit)

    @app.get("/api/failures-per-hour")
    def failures_per_hour():
        return db.failures_per_hour(db_path)

    @app.get("/")
    def dashboard():
        return FileResponse(STATIC_DIR / "index.html")

    return app
