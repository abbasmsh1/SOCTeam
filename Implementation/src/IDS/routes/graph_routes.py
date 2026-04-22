"""Incident-graph endpoints — extracted from IDS.py."""

from __future__ import annotations

from fastapi import Depends, HTTPException


def register(app, *, verify_api_key) -> None:
    @app.get("/graph/summary", dependencies=[Depends(verify_api_key)])
    def graph_summary():
        from Implementation.src.IDS.incident_graph import get_incident_graph
        try:
            return get_incident_graph().summary()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/graph/ip/{ip}", dependencies=[Depends(verify_api_key)])
    def graph_ip(ip: str, limit: int = 25):
        from Implementation.src.IDS.incident_graph import get_incident_graph
        try:
            return {"ip": ip, "incidents": get_incident_graph().incidents_for_ip(ip, limit=limit)}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/graph/attack/{attack_type}", dependencies=[Depends(verify_api_key)])
    def graph_attack(attack_type: str, limit: int = 25):
        from Implementation.src.IDS.incident_graph import get_incident_graph
        try:
            return {"attack": attack_type, "ips": get_incident_graph().ips_for_attack(attack_type, limit=limit)}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))
