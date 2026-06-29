# Infrastructure as Code

> *"Your triage system is only as reliable as the infrastructure it runs on. A perfect prompt means nothing if your container can't survive a cold start, and a flawless model is useless if the endpoint isn't reachable. Deploy it like you're launching a hull repair drone — test it, trust it, and make sure it comes back."*
> — Chief Signal Officer Mehta, margin note on the station's IaC runbook

The `infra/` folder contains the Pulumi program for deploying the FDEBench API
to Azure Container Apps. It codifies the live topology used for the submission:
Azure Resource Group, Azure Container Registry, user-assigned managed identity
with `AcrPull`, Log Analytics, Application Insights, Container Apps managed
environment, and the public HTTPS Container App.

## Project layout

```
infra/
└── app/
    ├── __main__.py      # Azure Native Pulumi program
    ├── Pulumi.yml       # Project settings
    └── pyproject.toml   # Pulumi + Azure Native dependencies
```

## Getting started

```powershell
cd infra/app
uv sync
pulumi login --local
pulumi stack select dev --create

pulumi config set azure-native:location eastus
pulumi config set location eastus
pulumi config set resourceGroupName rg-fde-hackathon
pulumi config set acrName <globally-unique-acr-name>
pulumi config set containerAppsEnvironmentName fde-aca-env
pulumi config set containerAppName fde-triage-api
pulumi config set imageRepository fde-triage
pulumi config set imageTag latest

pulumi config set azureOpenAiEndpoint https://<your-aoai-resource>.openai.azure.com/
pulumi config set azureOpenAiApiKey <your-key> --secret
pulumi config set aoaiDeployment gpt-5.4-mini
pulumi config set aoaiVisionDeployment gpt-5.4-mini

pulumi up
```

Build and push the container image before or after provisioning the registry:

```powershell
cd ../../
az acr build --registry <acr-name> --image fde-triage:latest .\py
```

The Azure OpenAI key is stored as a Pulumi secret and injected into the Container
App as a Container Apps secret. Image pulls use managed identity instead of ACR
admin credentials, and no secrets are committed to the repository.
