# 1-identity-keycloak

NestJS + Keycloak lesson demonstrating:
- Standard login via Keycloak token endpoint (`grant_type=password`)
- Google login via Keycloak identity brokering (`authorization_code`)
- Protected API (`/api/orders`) secured by `nest-keycloak-connect`

## Folder layout

```text
1-identity-keycloak/
├── .docker/
│   ├── backend.yaml      # Infra stack (postgres + keycloak)
│   ├── keycloak.yaml     # Infra stack alias
│   └── api-service.yaml  # Business service stack
├── .containers/
│   └── keycloak/import/starci-realm.json
├── api-service/
│   ├── src/
│   ├── Dockerfile
│   ├── package.json
│   └── tsconfig.json
└── README.md
```

## Workflow (Prepare -> Sign -> Execute -> Confirm)

### 1) Prepare

```bash
docker network create starci-network
```

### 2) Sign

Review key configs:
- `.docker/keycloak.yaml`
- `.docker/api-service.yaml`
- `.containers/keycloak/import/starci-realm.json`

### 3) Execute

Start infrastructure:

```bash
docker compose -f .docker/keycloak.yaml up -d
```

Start API service (from source):

```bash
cd api-service
npm install
npm run start:dev
```

Or run API service by Compose:

```bash
docker compose -f .docker/api-service.yaml up -d --build
```

### 4) Confirm

Unauthenticated request should be blocked:

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/orders
```

Password login:

```bash
curl -s -X POST "http://localhost:3000/auth/login/password" \
  -H "Content-Type: application/json" \
  -d '{"username":"student","password":"student123"}'
```

Use `access_token` to call protected endpoint:

```bash
curl -s "http://localhost:3000/api/orders" \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

## Google login (optional)

1. Configure Google IdP in Keycloak admin (`starci-realm`).
2. Fetch URL:

```bash
curl -s "http://localhost:3000/auth/google/url"
```

3. Open `authorizeUrl`, login with Google, capture `code`.
4. Exchange token:

```bash
curl -s "http://localhost:3000/auth/callback?code=<AUTHORIZATION_CODE>"
```

## Endpoints

- `POST /auth/login/password`
- `GET /auth/google/url`
- `GET /auth/callback?code=...`
- `GET /api/orders` (Bearer token required)

## Library

- [`nest-keycloak-connect`](https://www.npmjs.com/package/nest-keycloak-connect)
