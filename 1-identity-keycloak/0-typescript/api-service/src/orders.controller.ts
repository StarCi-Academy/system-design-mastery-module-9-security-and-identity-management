/**
 * OrdersController — protected resource; requires a valid Bearer token from Keycloak.
 */
import {
    Controller,
    Get,
} from "@nestjs/common"
import {
    AuthenticatedUser,
} from "nest-keycloak-connect"
import type {
    KeycloakUser,
} from "./types"

@Controller("api/orders")
export class OrdersController {
    /** Returns demo orders — only reachable with a valid Bearer token. */
    @Get()
    listOrders(@AuthenticatedUser() user: KeycloakUser): {
        status: string
        message: string
        data: Array<{ id: number; total: number }>
    } {
        const username = user?.preferred_username ?? user?.email ?? "user"
        return {
            status: "success",
            message: `Welcome ${username}. Here are your orders`,
            data: [
                { id: 1, total: 500 },
                { id: 2, total: 1000 },
            ],
        }
    }
}
