# 🛰️ Infrastructure as Code — Deploying to Orbit

> *"Your triage system is only as reliable as the infrastructure it runs on. A perfect prompt means nothing if your container can't survive a cold start, and a flawless model is useless if the endpoint isn't reachable. Deploy it like you're launching a hull repair drone — test it, trust it, and make sure it comes back."*
> — Chief Signal Officer Mehta, margin note on the station's IaC runbook

The `infra/` folder contains infrastructure as code (IaC) configurations for provisioning and managing cloud resources using [Pulumi](https://www.pulumi.com/) with [Python and uv](https://www.pulumi.com/docs/iac/languages-sdks/python/#uv). Think of it as your station blueprint — except this station runs in Azure instead of orbiting at 0.3 AU.

## Project layout

```
infra/
└── app/
    ├── __main__.py      # Pulumi program — your orbital deployment manifest
    ├── Pulumi.yml       # Project settings — station configuration
    └── pyproject.toml   # Python dependencies (Pulumi SDK, Azure SDKs, etc.)
```

## Getting started

```bash
cd infra/app
uv sync
pulumi login --local
export PULUMI_CONFIG_PASSPHRASE=$(openssl rand -hex 32)
pulumi stack select dev --create
pulumi up
```

For more details, see [Pulumi's documentation](https://www.pulumi.com/docs/).

> **Tip from Station Ops:** Deploy early. The number of operators who deploy at hour 23 and then discover their container won't start is... nonzero. Much like hull breach drills, the best time to test your deployment is before the emergency. The second-best time is not 30 minutes before submission. The scoring computer cannot reach localhost, and neither can Commander Kapoor's patience.
