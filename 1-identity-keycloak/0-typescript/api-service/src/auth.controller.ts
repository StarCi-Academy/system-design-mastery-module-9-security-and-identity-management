/**
 * AuthController — login (public/confidential), authorize URL, and OIDC callback.
 */
import {
    Body,
    Controller,
    Get,
    Post,
    Query,
} from "@nestjs/common"
import {
    Public,
} from "nest-keycloak-connect"
import {
    KeycloakService,
} from "./keycloak.service"
import type {
    TokenResponse,
} from "./types"

/** Request body for the password grant flows. */
type PasswordLoginBody = {
    username?: string
    password?: string
}

@Controller("auth")
export class AuthController {
    constructor(private readonly keycloakService: KeycloakService) {}

    /** Login via the public client (Direct Access Grants, no secret). */
    @Public()
    @Post("login/public")
    loginPublic(@Body() body: PasswordLoginBody): Promise<TokenResponse> {
        return this.keycloakService.loginPublicClient(body.username, body.password)
    }

    /** Login via the confidential client (sends client_secret). */
    @Public()
    @Post("login/private")
    loginPrivate(@Body() body: PasswordLoginBody): Promise<TokenResponse> {
        return this.keycloakService.loginPrivateClient(body.username, body.password)
    }

    /** Return the authorize URL to redirect the browser to Keycloak login. */
    @Public()
    @Get("authorize/url")
    authorizeUrl(): { authorizeUrl: string; note: string } {
        return {
            authorizeUrl: this.keycloakService.getAuthorizeUrl(),
            note: "Open authorizeUrl in browser, then copy `code` from callback query params.",
        }
    }

    /** Callback: exchange the authorization code for an access token. */
    @Public()
    @Get("callback")
    exchangeCode(@Query("code") code?: string): Promise<TokenResponse> {
        return this.keycloakService.exchangeCode(code ?? "")
    }
}
