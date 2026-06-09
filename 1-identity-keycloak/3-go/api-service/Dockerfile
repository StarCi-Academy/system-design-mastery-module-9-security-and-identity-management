# Multi-stage build for the Go Identity & Keycloak API service.

# --- Build stage -----------------------------------------------------------
FROM golang:1.22-alpine AS build
WORKDIR /src

# Resolve dependencies first (cached when go.mod is unchanged).
COPY go.mod ./
RUN go mod download github.com/coreos/go-oidc/v3 || true

# Copy sources and build a static binary.
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api-service .

# --- Runtime stage ---------------------------------------------------------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=build /out/api-service /app/api-service
EXPOSE 3000
ENTRYPOINT ["/app/api-service"]
