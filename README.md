# system-design-mastery-module-8-security-and-identity-management

Security and identity management demos for System Design Mastery.

## Lessons

- `1-identity-keycloak`: NestJS + Keycloak SSO, password login, and Google identity brokering flow

## Quick start

```bash
docker network create starci-network
```

Run any lesson with:

```bash
cd <lesson-folder>
docker compose -f .docker/backend.yaml up -d --build
```

## Comment & cấu trúc (strict §4)
- `compose.yaml`: header + comment từng service (VI + EN).
- `*.service.ts` / `*.controller.ts`: mọi method có JSDoc **Logic —** + **Code —** + EN Logic/Code.
- Regenerate: `node scratch/comment_system_design_modules_1_11.mjs`

