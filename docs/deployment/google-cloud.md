<!-- meta:title Google Cloud -->
<!-- meta:description Deploy the Falcon MCP Server on Google Cloud Run. -->
<!-- meta:section deployment -->
<!-- meta:link-base /falcon-mcp/ -->

This guide covers deploying the Falcon MCP Server container on Google Cloud Run.

## Prerequisites

- `gcloud` CLI installed and authenticated
- Google Cloud project with billing enabled
- CrowdStrike API credentials
- Permission to deploy Cloud Run services and push to Artifact Registry (or use the published image)

## Deploy the container to Cloud Run

Use the published container image (or build from this repository's `Dockerfile`):

```bash
gcloud run deploy falcon-mcp \
  --image ghcr.io/crowdstrike/falcon-mcp:latest \
  --region YOUR-REGION \
  --port 8000 \
  --set-env-vars "FALCON_CLIENT_ID=...,FALCON_CLIENT_SECRET=...,FALCON_MCP_TRANSPORT=streamable-http,FALCON_MCP_HOST=0.0.0.0,FALCON_MCP_PORT=8000" \
  --set-env-vars "FALCON_MCP_API_KEY=your-secret-key" \
  --allow-unauthenticated=false
```

> [!CAUTION]
> Always set `FALCON_MCP_API_KEY` (or terminate TLS and auth at a fronting proxy) when the service
> is reachable beyond loopback. See
> [HTTP Transport Security](/falcon-mcp/getting-started/configuration/#http-transport-security).

Once deployed, grant access to your team:

1. Cloud Run > Services > `falcon-mcp` > Permissions
2. Add Principal > assign `Cloud Run Invoker` role

Proxy the service locally:

```bash
gcloud run services proxy falcon-mcp --project PROJECT-ID --region YOUR-REGION
```

Point MCP clients at the proxied or public HTTPS `/mcp` endpoint. See
[Editor Integration](/falcon-mcp/usage/editor-integration/) and
[Docker deployment](/falcon-mcp/deployment/docker/) for more options.
