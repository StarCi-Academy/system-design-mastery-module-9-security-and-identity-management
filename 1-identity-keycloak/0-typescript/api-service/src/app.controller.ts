/**
 * AppController — health probe and available endpoint listing (public).
 */
import {
    Controller,
    Get,
} from "@nestjs/common"
import {
    Public,
} from "nest-keycloak-connect"
import type {
    HealthResponse,
} from "./types"

@Controller()
export class AppController {
    /** Minimal root probe — confirms the API is running and lists demo endpoints. */
    @Public()
    @Get()
    health(): HealthResponse {
        return {
            status: "ok",
            message: "Identity Keycloak NestJS demo is running.",
            endpoints: {
                loginPublic: "POST /auth/login/public",
                loginPrivate: "POST /auth/login/private",
                authorizeUrl: "GET /auth/authorize/url",
                authCallback: "GET /auth/callback?code=...",
                protectedOrders: "GET /api/orders (requires Bearer token)",
            },
        }
    }
}
