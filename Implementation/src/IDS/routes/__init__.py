"""
Route modules extracted from IDS.py.

Each file exposes a `register(app, *, verify_api_key, verify_admin_api_key, **ctx)`
function that attaches its routes to the FastAPI app. Keep each file focused
— ~200 lines — so contract tests can exercise them independently.

Currently extracted:
  - rl_routes.py       — /rl/stats, /rl/feedback, /rl/train, /rl/policy
  - graph_routes.py    — /graph/summary, /graph/ip/{ip}, /graph/attack/{attack}

Next candidates:
  - quarantine_routes.py
  - capture_routes.py
  - metrics_routes.py
"""
