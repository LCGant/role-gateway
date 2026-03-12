# Gateway

[Read in English](README.md) | [Raiz do projeto](../README.pt-BR.md)

O gateway e a borda publica da plataforma. Ele recebe o trafego de clientes, aplica endurecimento HTTP, bloqueia caminhos internos e encaminha o trafego permitido para os servicos internos.

## Responsabilidades

- expor a entrada HTTP publica
- encaminhar trafego de autenticacao para o `auth`
- encaminhar trafego publico de aplicacao para servicos downstream
- bloquear acesso direto a caminhos internos como `auth/internal`, endpoints de decisao do `pdp`, `notification` e `audit`
- aplicar limites de corpo, timeouts, headers de seguranca e rate limit

## O que ele nao e

O gateway nao e um segundo servico de autenticacao e nao deve carregar regra de negocio de autorizacao. Autenticacao fica no `auth`. Decisao de policy fica no `pdp`.

## Postura de seguranca

- falha fechada para configuracao invalida de upstream
- tratamento explicito de proxies confiaveis por CIDR
- limite de body antes do proxy
- headers de seguranca via middleware compartilhado
- superficie publica intencionalmente curta

## Estado atual

Este componente ja e utilizavel e foi desenhado com foco em seguranca. Ainda assim, ele deve ser visto como ponto de partida e nao como edge platform final. Quem adotar precisa complementar observabilidade, controles operacionais e detalhes de proxy/TLS do ambiente real.
