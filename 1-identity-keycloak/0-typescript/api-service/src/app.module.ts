/**
 * Root module — global ConfigModule, the Keycloak guard stack, and controllers.
 * Keycloak uses the public client for offline JWT validation; KeycloakService also
 * demos the confidential client for the password-grant flow.
 */
import {
    Module,
} from "@nestjs/common"
import {
    APP_GUARD,
} from "@nestjs/core"
import {
    ConfigModule,
    ConfigService,
} from "@nestjs/config"
import {
    AuthGuard,
    KeycloakConnectModule,
    PolicyEnforcementMode,
    ResourceGuard,
    RoleGuard,
    TokenValidation,
} from "nest-keycloak-connect"
import {
    AppController,
} from "./app.controller"
import {
    AuthController,
} from "./auth.controller"
import {
    KeycloakService,
} from "./keycloak.service"
import {
    OrdersController,
} from "./orders.controller"

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
        }),
        KeycloakConnectModule.registerAsync({
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                authServerUrl: config.get<string>("KEYCLOAK_BASE_URL", "http://keycloak:8080"),
                realm: config.get<string>("KEYCLOAK_REALM", "starci-realm"),
                clientId: config.get<string>("KEYCLOAK_PUBLIC_CLIENT_ID", "nestjs-app"),
                secret: "",
                policyEnforcement: PolicyEnforcementMode.PERMISSIVE,
                tokenValidation: TokenValidation.OFFLINE,
            }),
        }),
    ],
    controllers: [
        AppController,
        AuthController,
        OrdersController,
    ],
    providers: [
        KeycloakService,
        // Keycloak guard stack — AuthGuard -> ResourceGuard -> RoleGuard (global).
        { provide: APP_GUARD, useClass: AuthGuard },
        { provide: APP_GUARD, useClass: ResourceGuard },
        { provide: APP_GUARD, useClass: RoleGuard },
    ],
})
export class AppModule {}
