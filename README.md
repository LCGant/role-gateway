# Role Gateway

[Leia em Portugues](README.pt-BR.md) | [Workspace root](https://github.com/LCGant/role-root)

Role Gateway is a Go-based foundation for secure request routing and internal service boundary protection. This repository contains the public gateway service, shared Go utilities used by that edge layer, and smoke tooling for validating the integrated stack.

## What this repository contains

- `gateway`: public edge gateway
- `libs/common`: shared Go middleware and HTTP utilities
- `tools/smoke`: smoke checks used against the integrated platform

## Status

This repository is a solid starting point for teams building a security-focused gateway in Go. It is not presented as a fully finished platform. Some integrations and operational layers are intentionally still basic, which makes this a practical foundation rather than a turnkey product.