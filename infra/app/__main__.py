"""Azure Container Apps deployment for the FDEBench API.

This Pulumi program codifies the resources used by the live submission:
resource group, Azure Container Registry, Log Analytics, Application Insights,
Container Apps environment, and public HTTPS Container App. Secrets are Pulumi
config values, never source-controlled.
"""

from uuid import NAMESPACE_URL, uuid5

import pulumi
from pulumi_azure_native import app
from pulumi_azure_native import applicationinsights
from pulumi_azure_native import authorization
from pulumi_azure_native import containerregistry
from pulumi_azure_native import managedidentity
from pulumi_azure_native import operationalinsights
from pulumi_azure_native import resources

config = pulumi.Config()

location = config.get("location") or "eastus"
resource_group_name = config.get("resourceGroupName") or "rg-fde-hackathon"
acr_name = config.get("acrName") or "fdehackdyh8j"
environment_name = config.get("containerAppsEnvironmentName") or "fde-aca-env"
container_app_name = config.get("containerAppName") or "fde-triage-api"
image_repository = config.get("imageRepository") or "fde-triage"
image_tag = config.get("imageTag") or "latest"
cpu = config.get_float("cpu") or 1.0
memory = config.get("memory") or "2Gi"
min_replicas = config.get_int("minReplicas") or 1
max_replicas = config.get_int("maxReplicas") or 5

aoai_endpoint = config.get("azureOpenAiEndpoint") or ""
aoai_api_key = config.get_secret("azureOpenAiApiKey") or pulumi.Output.secret("")
aoai_api_version = config.get("azureOpenAiApiVersion") or "2024-10-21"
aoai_deployment = config.get("aoaiDeployment") or "gpt-5.4-mini"
aoai_vision_deployment = config.get("aoaiVisionDeployment") or aoai_deployment
model_name = config.get("modelName") or aoai_deployment
reasoning_effort = config.get("reasoningEffort") or "minimal"
triage_reasoning_effort = config.get("triageReasoningEffort") or "minimal"
vision_reasoning_effort = config.get("visionReasoningEffort") or "low"
orchestrate_reasoning_effort = config.get("orchestrateReasoningEffort") or "medium"
vision_detail = config.get("visionDetail") or "high"

tags = {
    "app": "fdebench",
    "owner": "dheeraj1022",
    "workload": "hackathon",
}
acr_pull_role_id = "7f951dda-4ed3-4680-a7ca-43fe172d538d"

resource_group = resources.ResourceGroup(
    "fde-rg",
    resource_group_name=resource_group_name,
    location=location,
    tags=tags,
)

registry = containerregistry.Registry(
    "fde-acr",
    registry_name=acr_name,
    resource_group_name=resource_group.name,
    location=resource_group.location,
    admin_user_enabled=False,
    sku=containerregistry.SkuArgs(name="Basic"),
    tags=tags,
)

container_identity = managedidentity.UserAssignedIdentity(
    "fde-api-identity",
    resource_name_=f"{container_app_name}-identity",
    resource_group_name=resource_group.name,
    location=resource_group.location,
    tags=tags,
)

acr_pull_role = authorization.get_role_definition_output(
    role_definition_id=acr_pull_role_id,
    scope=registry.id,
)

acr_pull_assignment = authorization.RoleAssignment(
    "fde-acr-pull",
    role_assignment_name=str(
        uuid5(NAMESPACE_URL, f"{resource_group_name}/{acr_name}/{container_app_name}/acr-pull")
    ),
    principal_id=container_identity.principal_id,
    principal_type="ServicePrincipal",
    role_definition_id=acr_pull_role.apply(lambda role: role.id),
    scope=registry.id,
)

workspace = operationalinsights.Workspace(
    "fde-logs",
    workspace_name=f"{container_app_name}-logs",
    resource_group_name=resource_group.name,
    location=resource_group.location,
    retention_in_days=30,
    sku=operationalinsights.WorkspaceSkuArgs(name="PerGB2018"),
    tags=tags,
)

workspace_keys = operationalinsights.get_shared_keys_output(
    resource_group_name=resource_group.name,
    workspace_name=workspace.name,
)

app_insights = applicationinsights.Component(
    "fde-appinsights",
    resource_name_=f"{container_app_name}-appi",
    resource_group_name=resource_group.name,
    location=resource_group.location,
    kind="web",
    application_type="web",
    workspace_resource_id=workspace.id,
    tags=tags,
)

managed_environment = app.ManagedEnvironment(
    "fde-aca-env",
    environment_name=environment_name,
    resource_group_name=resource_group.name,
    location=resource_group.location,
    app_logs_configuration=app.AppLogsConfigurationArgs(
        destination="log-analytics",
        log_analytics_configuration=app.LogAnalyticsConfigurationArgs(
            customer_id=workspace.customer_id,
            shared_key=workspace_keys.primary_shared_key,
        ),
    ),
    public_network_access="Enabled",
    tags=tags,
)

image = pulumi.Output.concat(registry.login_server, "/", image_repository, ":", image_tag)

container_app = app.ContainerApp(
    "fde-api",
    container_app_name=container_app_name,
    resource_group_name=resource_group.name,
    location=resource_group.location,
    environment_id=managed_environment.id,
    identity=app.ManagedServiceIdentityArgs(
        type="UserAssigned",
        user_assigned_identities=[container_identity.id],
    ),
    configuration=app.ConfigurationArgs(
        active_revisions_mode="Single",
        ingress=app.IngressArgs(
            external=True,
            target_port=8000,
            transport="auto",
            traffic=[app.TrafficWeightArgs(latest_revision=True, weight=100)],
        ),
        registries=[
            app.RegistryCredentialsArgs(
                server=registry.login_server,
                identity=container_identity.id,
            )
        ],
        secrets=[
            app.SecretArgs(name="aoai-key", value=aoai_api_key),
        ],
    ),
    template=app.TemplateArgs(
        containers=[
            app.ContainerArgs(
                name="fde-api",
                image=image,
                resources=app.ContainerResourcesArgs(cpu=cpu, memory=memory),
                env=[
                    app.EnvironmentVarArgs(name="AZURE_OPENAI_ENDPOINT", value=aoai_endpoint),
                    app.EnvironmentVarArgs(name="AZURE_OPENAI_API_KEY", secret_ref="aoai-key"),
                    app.EnvironmentVarArgs(name="AZURE_OPENAI_API_VERSION", value=aoai_api_version),
                    app.EnvironmentVarArgs(name="AOAI_DEPLOYMENT", value=aoai_deployment),
                    app.EnvironmentVarArgs(name="AOAI_VISION_DEPLOYMENT", value=aoai_vision_deployment),
                    app.EnvironmentVarArgs(name="MODEL_NAME", value=model_name),
                    app.EnvironmentVarArgs(name="REASONING_EFFORT", value=reasoning_effort),
                    app.EnvironmentVarArgs(name="TRIAGE_REASONING_EFFORT", value=triage_reasoning_effort),
                    app.EnvironmentVarArgs(name="VISION_REASONING_EFFORT", value=vision_reasoning_effort),
                    app.EnvironmentVarArgs(
                        name="ORCHESTRATE_REASONING_EFFORT",
                        value=orchestrate_reasoning_effort,
                    ),
                    app.EnvironmentVarArgs(name="VISION_DETAIL", value=vision_detail),
                    app.EnvironmentVarArgs(
                        name="APPLICATIONINSIGHTS_CONNECTION_STRING",
                        value=app_insights.connection_string,
                    ),
                ],
            )
        ],
        scale=app.ScaleArgs(min_replicas=min_replicas, max_replicas=max_replicas),
    ),
    tags=tags,
    opts=pulumi.ResourceOptions(depends_on=[acr_pull_assignment]),
)

pulumi.export("resource_group", resource_group.name)
pulumi.export("acr_login_server", registry.login_server)
pulumi.export("container_app_name", container_app.name)
pulumi.export("container_identity_client_id", container_identity.client_id)
pulumi.export("container_app_url", pulumi.Output.concat("https://", container_app.configuration.ingress.fqdn))
pulumi.export("app_insights_connection_string", pulumi.Output.secret(app_insights.connection_string))
