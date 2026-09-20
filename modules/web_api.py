# modules/web_api.py
"""
SentinelX - Web API
REST API for SentinelX (FastAPI).

Optional dependency: pip install fastapi uvicorn
"""

import os
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("SentinelX.web_api")

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


if HAS_FASTAPI:
    app = FastAPI(
        title="SentinelX API",
        description="Blue Team Security Suite REST API",
        version="2.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Models
    class PathRequest(BaseModel):
        path: str

    class PhoneRequest(BaseModel):
        number: str

    # Endpoints
    @app.get("/")
    def root():
        return {
            "name": "SentinelX API",
            "version": "2.1.0",
            "endpoints": [
                "/health",
                "/scan/file",
                "/scan/path",
                "/ioc/stats",
                "/alerts/recent",
                "/phone",
                "/yara",
            ]
        }

    @app.get("/health")
    def health():
        return {"status": "ok", "timestamp": datetime.now().isoformat()}

    @app.post("/scan/file")
    def scan_file(req: PathRequest):
        try:
            from modules.ioc_hunter import scan_path
            return scan_path(req.path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/scan/path")
    def scan_path_endpoint(req: PathRequest):
        try:
            from modules.ioc_hunter import scan_path
            return scan_path(req.path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/ioc/stats")
    def ioc_stats():
        try:
            from modules.ioc_hunter import load_local_iocs
            iocs = load_local_iocs()
            return {"count": len(iocs)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/alerts/recent")
    def recent_alerts(limit: int = 20):
        try:
            from modules.cache_db import get_recent_alerts
            return get_recent_alerts(limit)
        except Exception as e:
            return {"alerts": [], "error": str(e)}

    @app.post("/phone")
    def phone_osint(req: PhoneRequest):
        try:
            from modules.phone_osint import analyze_phone_number
            return analyze_phone_number(req.number)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/yara")
    def yara_scan(req: PathRequest):
        try:
            from modules.yara_engine import scan_directory
            return scan_directory(req.path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


def run_server(host="0.0.0.0", port=8080):
    """Run the API server."""
    if not HAS_FASTAPI:
        print("[!] FastAPI not installed.")
        print("    Run: pip install fastapi uvicorn")
        return

    try:
        import uvicorn
    except ImportError:
        print("[!] uvicorn not installed.")
        print("    Run: pip install uvicorn")
        return

    print(f"\n[*] Starting SentinelX API on http://{host}:{port}")
    print(f"[*] Docs: http://{host}:{port}/docs")
    print()

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_server()
