# Role Gateway

[Read in English](README.md) | [Workspace root](https://github.com/LCGant/role-root)

Role Gateway e uma base em Go para roteamento seguro de requisicoes e protecao de fronteiras internas entre servicos. Este repositorio contem o servico publico de gateway, utilitarios Go compartilhados usados nessa borda e o smoke tooling para validar o stack integrado.

## O que existe neste repositorio

- `gateway`: gateway de borda publica
- `libs/common`: middlewares e utilitarios HTTP compartilhados em Go
- `tools/smoke`: smoke checks usados contra a plataforma integrada

## Estado atual

Este repositorio ja e um bom ponto de partida para equipes que querem um gateway com foco em seguranca em Go. Ele nao esta sendo apresentado como plataforma totalmente finalizada. Algumas integracoes e camadas operacionais continuam intencionalmente basicas, o que faz daqui uma fundacao pratica e nao um produto turnkey.