FROM golang:1.26.1-alpine AS builder
WORKDIR /src
COPY tools/smoke/go.mod ./tools/smoke/go.mod
WORKDIR /src/tools/smoke
RUN go mod download
COPY tools/smoke ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/smoke ./cmd/smoke

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/smoke /app/smoke
ENTRYPOINT ["/app/smoke"]
