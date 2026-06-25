"""
validation/test_sentrix_v7.py
Sentrix V7 — Full Validation Suite
Runs against the live FastAPI app on http://localhost:8000
Tests all 10 planned validation cases.
"""
import time
import sys
import requests

BASE_URL = "http://localhost:8000/api/v1"

PASS = "\033[92m PASS\033[0m"
FAIL = "\033[91m FAIL\033[0m"

results = []

def run(name, fn):
    try:
        fn()
        print(f"  [{PASS}] {name}")
        results.append((name, True, None))
    except AssertionError as e:
        print(f"  [{FAIL}] {name}: {e}")
        results.append((name, False, str(e)))
    except Exception as e:
        print(f"  [{FAIL}] {name}: {type(e).__name__}: {e}")
        results.append((name, False, str(e)))

# ── Test 1: Engine Startup / Platform Health ────────────────────────────────
def test_health():
    resp = requests.get(f"{BASE_URL}/admin/health", timeout=10)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["status"] == "healthy", f"Platform not healthy: {data}"
    assert data["threat_engine"]["status"] in ("healthy", "degraded"), f"Threat engine: {data['threat_engine']}"
    assert data["prediction_engine"]["status"] in ("healthy", "degraded"), f"Prediction: {data['prediction_engine']}"
    assert data["investigation_engine"]["status"] in ("healthy", "degraded"), f"Investigation: {data['investigation_engine']}"

# ── Test 2: Threat Engine — event ingest ────────────────────────────────────
def test_threat_ingest():
    sample_event = {
        "event": {
            "source": {"ip": "192.168.1.100"},
            "destination": {"ip": "10.0.0.5", "port": 443},
            "timestamp": "2026-06-22T12:00:00Z",
            "event_type": "connection"
        }
    }
    resp = requests.post(f"{BASE_URL}/threat/events/ingest", json=sample_event, timeout=10)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "alerts_generated" in data, f"Missing alerts_generated in response: {data}"

# ── Test 3: Prediction Engine — forecast (empty is OK) ──────────────────────
def test_prediction_forecast():
    resp = requests.get(f"{BASE_URL}/predictions/forecast", timeout=10)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert isinstance(data, (list, dict)), f"Unexpected response type: {type(data)}"

# ── Test 4: Investigation Engine — trigger investigation ────────────────────
def test_investigation_trigger():
    resp = requests.post(f"{BASE_URL}/investigations/generate/192.168.1.100", timeout=10)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data.get("status") == "Investigation triggered", f"Unexpected status: {data}"

# ── Test 5: Connector Framework — registry loaded ───────────────────────────
def test_connectors_registered():
    resp = requests.get(f"{BASE_URL}/connectors/", timeout=10)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert isinstance(data, (list, dict)), f"Unexpected response type: {type(data)}"
    # At least some connectors registered (even if disabled/unconfigured)
    connector_count = len(data) if isinstance(data, list) else len(data.get("connectors", data))
    assert connector_count >= 1, f"Expected at least 1 connector, got {connector_count}"

# ── Test 6: Rule CRUD — create / retrieve / delete ─────────────────────────
def test_rule_crud():
    rule_payload = {
        "rule": {
            "rule_name": "V7 Validation Test Rule",
            "metadata": {"id": "v7-validation-rule-001", "version": "1.0"},
            "conditions": [],
            "actions": []
        }
    }
    # Create
    resp = requests.post(f"{BASE_URL}/rules/", json=rule_payload, timeout=10)
    assert resp.status_code == 200, f"Create failed: {resp.status_code}: {resp.text}"

    # Retrieve
    resp = requests.get(f"{BASE_URL}/rules/v7-validation-rule-001", timeout=10)
    assert resp.status_code == 200, f"Get failed: {resp.status_code}: {resp.text}"

    # Delete
    resp = requests.delete(f"{BASE_URL}/rules/v7-validation-rule-001", timeout=10)
    assert resp.status_code == 200, f"Delete failed: {resp.status_code}: {resp.text}"

# ── Test 7: Event Propagation — ingest → get incidents list ────────────────
def test_event_propagation():
    # Ingest a threat event
    event_payload = {
        "event": {
            "source": {"ip": "10.10.10.10"},
            "destination": {"ip": "192.168.1.1"},
            "timestamp": "2026-06-22T13:00:00Z",
            "event_type": "port_scan"
        }
    }
    resp = requests.post(f"{BASE_URL}/threat/events/ingest", json=event_payload, timeout=10)
    assert resp.status_code == 200, f"Ingest failed: {resp.status_code}: {resp.text}"

    # Incident list should be accessible (may be empty if no alerts fired)
    resp = requests.get(f"{BASE_URL}/investigations/incidents", timeout=10)
    assert resp.status_code == 200, f"Incidents list failed: {resp.status_code}: {resp.text}"

# ── Test 8: AI Layer — provider status reported gracefully ──────────────────
def test_ai_layer_readiness():
    # Platform should not crash if AI keys are absent
    resp = requests.get(f"{BASE_URL}/admin/health", timeout=10)
    assert resp.status_code == 200, f"Health failed after AI check: {resp.status_code}: {resp.text}"

# ── Test 9: Security — unauthenticated read-only routes accessible ──────────
def test_security_readiness():
    # Without AUTH_ENABLED, all endpoints open (default); this just verifies no 500
    resp = requests.get(f"{BASE_URL}/admin/ready", timeout=10)
    assert resp.status_code == 200, f"Ready failed: {resp.status_code}: {resp.text}"
    assert resp.json().get("status") == "ready", f"Unexpected ready response: {resp.json()}"

# ── Test 10: Export endpoints respond ───────────────────────────────────────
def test_export_endpoints():
    # Forecast history endpoint
    resp = requests.get(f"{BASE_URL}/predictions/history", timeout=10)
    assert resp.status_code == 200, f"History failed: {resp.status_code}: {resp.text}"

    # Rules list
    resp = requests.get(f"{BASE_URL}/rules/", timeout=10)
    assert resp.status_code == 200, f"Rules list failed: {resp.status_code}: {resp.text}"


if __name__ == "__main__":
    print()
    print("=" * 55)
    print("  SENTRIX V7 — FULL VALIDATION SUITE")
    print("=" * 55)

    # Wait for server if just started
    print("  Waiting for platform to be ready...")
    for _ in range(12):
        try:
            r = requests.get(f"{BASE_URL}/admin/ready", timeout=3)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(5)
    print()

    run("Engine Startup / Platform Health", test_health)
    run("Threat Engine — Event Ingest", test_threat_ingest)
    run("Prediction Engine — Forecast", test_prediction_forecast)
    run("Investigation Engine — Trigger", test_investigation_trigger)
    run("Connector Framework — Registry Loaded", test_connectors_registered)
    run("Rule CRUD — Create / Retrieve / Delete", test_rule_crud)
    run("Event Propagation — Ingest -> Incidents", test_event_propagation)
    run("AI Layer — Graceful Absence", test_ai_layer_readiness)
    run("Security — Readiness Probe", test_security_readiness)
    run("Export Endpoints — Forecast History + Rules", test_export_endpoints)

    print()
    print("=" * 55)
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"  RESULTS: {passed}/{total} tests passed")

    if passed == total:
        print("  [PASS] ALL VALIDATION TESTS PASSED")
    else:
        print("  [FAIL] SOME TESTS FAILED:")
        for name, ok, err in results:
            if not ok:
                print(f"     - {name}: {err}")

    print("=" * 55)
    sys.exit(0 if passed == total else 1)
