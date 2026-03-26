# Gateway

[Leia em Portugues](README.pt-BR.md) | [Project root](../README.md)

The gateway is the public edge of the platform. It terminates client traffic, applies HTTP hardening, blocks internal-only paths, and proxies allowed traffic to internal services.

## Responsibilities

- expose the public HTTP entry point
- route user-facing auth traffic to `auth`
- route public authorization-aware application traffic to downstream services
- block direct access to internal-only paths such as `auth/internal`, `pdp` decision endpoints, `notification`, and `audit`
- enforce request size limits, timeouts, security headers, and rate limiting

## What it is not

The gateway is not a second auth service and it is not the place for business authorization logic. Authentication stays in `auth`. Policy decisions stay in `pdp`.

## Security posture

- fail-closed on invalid upstream configuration
- explicit handling for trusted proxy CIDRs
- request body limits before proxying
- security headers via shared middleware
- public route surface kept intentionally narrow

## Production TLS

- production traffic must reach the public edge over TLS
- the gateway supports direct TLS with `GATEWAY_TLS_CERT_FILE` and `GATEWAY_TLS_KEY_FILE`
- plaintext HTTP is only allowed with explicit `GATEWAY_ALLOW_PLAINTEXT_HTTP=true`
- when TLS is terminated by a reverse proxy or load balancer, keep plaintext disabled unless the internal hop is an intentional dev-only exception
- enable HSTS only after HTTPS is confirmed at the public edge

## Status

This component is usable and security-focused. It is still a starting point, not a finished edge platform. Teams adopting it should expect to refine observability, operational controls, and deployment-specific proxy/TLS behavior.
