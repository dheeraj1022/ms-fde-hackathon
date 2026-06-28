"""Tests for the in-memory metrics collector and its dashboard snapshot."""

from fde.metrics import Metrics


def test_records_counts_and_percentiles() -> None:
    m = Metrics()
    for ms in [10.0, 20.0, 30.0, 40.0, 100.0]:
        m.record("/triage", ms, 200, "gpt-5.4-mini")
    snap = m.snapshot()
    assert snap["total_requests"] == 5
    assert snap["total_errors"] == 0
    assert snap["model"] == "gpt-5.4-mini"
    route = next(r for r in snap["routes"] if r["path"] == "/triage")
    assert route["count"] == 5
    assert route["p50_ms"] == 30.0
    assert route["p95_ms"] == 100.0


def test_counts_5xx_as_errors_per_route() -> None:
    m = Metrics()
    m.record("/extract", 5.0, 200, "x")
    m.record("/extract", 5.0, 503, "x")
    snap = m.snapshot()
    assert snap["total_errors"] == 1
    route = next(r for r in snap["routes"] if r["path"] == "/extract")
    assert route["errors"] == 1


def test_empty_snapshot_is_safe() -> None:
    assert Metrics().snapshot()["routes"] == []
