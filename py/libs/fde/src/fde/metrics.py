"""In-memory metrics + a zero-dependency live dashboard for the served app.

The benchmark scores latency from response headers; this module gives a *human*
a live view of the same data — request volume, P50/P95 latency, error rate, and
model in use, per endpoint. State is a small ring buffer per route (bounded, no
external store) so it stays cheap and works in a single container. ``/metrics``
returns JSON; ``/dashboard`` serves a self-contained HTML page that polls it.
"""

import threading
import time
from collections import deque
from typing import Any

_MAX_SAMPLES = 500


def _pct(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


class Metrics:
    """Thread-safe, bounded request metrics for a single process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = time.time()
        self._total = 0
        self._errors = 0
        self._by_path: dict[str, deque[float]] = {}
        self._count_by_path: dict[str, int] = {}
        self._err_by_path: dict[str, int] = {}
        self._model = ""

    def record(self, path: str, latency_ms: float, status: int, model: str) -> None:
        """Record one completed request."""
        with self._lock:
            self._total += 1
            self._model = model or self._model
            self._by_path.setdefault(path, deque(maxlen=_MAX_SAMPLES)).append(latency_ms)
            self._count_by_path[path] = self._count_by_path.get(path, 0) + 1
            if status >= 500:
                self._errors += 1
                self._err_by_path[path] = self._err_by_path.get(path, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable view of current metrics."""
        with self._lock:
            routes = []
            for path, samples in sorted(self._by_path.items()):
                s = list(samples)
                routes.append(
                    {
                        "path": path,
                        "count": self._count_by_path.get(path, 0),
                        "errors": self._err_by_path.get(path, 0),
                        "p50_ms": round(_pct(s, 50), 1),
                        "p95_ms": round(_pct(s, 95), 1),
                    }
                )
            return {
                "uptime_s": round(time.time() - self._started, 1),
                "total_requests": self._total,
                "total_errors": self._errors,
                "model": self._model,
                "routes": routes,
            }


METRICS = Metrics()

DASHBOARD_HTML = """<!doctype html><html><head><meta charset=utf-8>
<title>FDE Triage — Live</title><style>
body{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#0b1020;color:#e6edf3}
h1{font-size:18px;margin:16px}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:0 16px}
.card{background:#161b2e;border:1px solid #2a3350;border-radius:10px;padding:14px 18px;min-width:140px}
.card .v{font-size:26px;font-weight:600}.card .l{font-size:12px;color:#8b96b0}
table{width:calc(100% - 32px);margin:16px;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3350;font-size:14px}
th{color:#8b96b0;font-weight:500}.err{color:#ff7b72}.ok{color:#3fb950}
</style></head><body><h1>FDE Triage — Live Operations</h1>
<div class=cards>
<div class=card><div class=v id=req>0</div><div class=l>requests</div></div>
<div class=card><div class=v id=err>0</div><div class=l>5xx errors</div></div>
<div class=card><div class=v id=model>-</div><div class=l>model</div></div>
<div class=card><div class=v id=up>0s</div><div class=l>uptime</div></div>
</div>
<table><thead><tr><th>endpoint</th><th>count</th><th>errors</th><th>p50</th><th>p95</th></tr></thead>
<tbody id=rows></tbody></table>
<script>
async function tick(){try{const m=await(await fetch('/metrics.json')).json();
req.textContent=m.total_requests;err.className=m.total_errors?'v err':'v ok';
err.textContent=m.total_errors;model.textContent=m.model||'-';up.textContent=m.uptime_s+'s';
rows.innerHTML=m.routes.map(r=>`<tr><td>${r.path}</td><td>${r.count}</td>
<td class=${r.errors?'err':''}>${r.errors}</td><td>${r.p50_ms}ms</td><td>${r.p95_ms}ms</td></tr>`).join('');
}catch(e){}}setInterval(tick,2000);tick();
</script></body></html>"""

__all__ = ["METRICS", "DASHBOARD_HTML", "Metrics"]
