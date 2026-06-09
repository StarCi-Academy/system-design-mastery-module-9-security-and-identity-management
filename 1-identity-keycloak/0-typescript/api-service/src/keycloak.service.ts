/**
 * KeycloakService — brokers token exchange with Keycloak (public + confidential client).
 */
import {
    BadRequestException,
    Injectable,
    Logger,
} from "@nestjs/common"
import {
    ConfigService,
} from "@nestjs/config"
import type {
    KeycloakErrorPayload,
    TokenResponse,
} from "./types"

@Injectable()
export class KeycloakService {
    private readonly logger = new Logger(KeycloakService.name)
    private readonly baseUrl: string
    private readonly realm: string
    private readonly publicClientId: string
    private readonly privateClientId: string
    private readonly privateClientSecret: string
    private readonly defaultUsername: string
    private readonly defaultPassword: string
    private readonly redirectUri: string

    constructor(private readonly config: ConfigService) {
        this.baseUrl = this.config.get<string>("KEYCLOAK_BASE_URL", "http://keycloak:8080")
        this.realm = this.config.get<string>("KEYCLOAK_REALM", "starci-realm")
        this.publicClientId = this.config.get<string>("KEYCLOAK_PUBLIC_CLIENT_ID", "nestjs-app")
        this.privateClientId = this.config.get<string>("KEYCLOAK_PRIVATE_CLIENT_ID", "nestjs-private-app")
        this.privateClientSecret = this.config.get<string>("KEYCLOAK_PRIVATE_CLIENT_SECRET", "super-secret-key")
        this.defaultUsername = this.config.get<string>("KEYCLOAK_DEFAULT_USERNAME", "student")
        this.defaultPassword = this.config.get<string>("KEYCLOAK_DEFAULT_PASSWORD", "student123")
        this.redirectUri = this.config.get<string>("KEYCLOAK_REDIRECT_URI", "http://localhost:3000/auth/callback")
    }

    private get tokenEndpoint(): string {
        return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/token`
    }

    private get authorizeEndpoint(): string {
        return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/auth`
    }

    /** Build the Authorization Code redirect URL for browser-based login. */
    getAuthorizeUrl(): string {
        const state = Math.random().toString(36).slice(2)
        const params = new URLSearchParams({
            client_id: this.publicClientId,
            response_type: "code",
            scope: "openid profile email",
            redirect_uri: this.redirectUri,
            state,
        })
        return `${this.authorizeEndpoint}?${params.toString()}`
    }

    /** Password grant via the public client (no secret). */
    async loginPublicClient(username?: string, password?: string): Promise<TokenResponse> {
        const effectiveUsername = username ?? this.defaultUsername
        const effectivePassword = password ?? this.defaultPassword
        const form = new URLSearchParams()
        form.set("client_id", this.publicClientId)
        form.set("grant_type", "password")
        form.set("username", effectiveUsername)
        form.set("password", effectivePassword)
        this.logger.log(`[public-client] Password grant for user=${effectiveUsername}`)
        return this.fetchToken(form)
    }

    /** Password grant via the confidential client (with client_secret). */
    async loginPrivateClient(username?: string, password?: string): Promise<TokenResponse> {
        const effectiveUsername = username ?? this.defaultUsername
        const effectivePassword = password ?? this.defaultPassword
        const form = new URLSearchParams()
        form.set("client_id", this.privateClientId)
        form.set("client_secret", this.privateClientSecret)
        form.set("grant_type", "password")
        form.set("username", effectiveUsername)
        form.set("password", effectivePassword)
        this.logger.log(`[private-client] Password grant for user=${effectiveUsername}`)
        return this.fetchToken(form)
    }

    /** Exchange an authorization code for tokens via the public client. */
    async exchangeCode(code: string): Promise<TokenResponse> {
        if (!code) {
            throw new BadRequestException("Missing `code` query param.")
        }
        const form = new URLSearchParams()
        form.set("client_id", this.publicClientId)
        form.set("grant_type", "authorization_code")
        form.set("code", code)
        form.set("redirect_uri", this.redirectUri)
        this.logger.log("[public-client] Exchange authorization_code with Keycloak")
        return this.fetchToken(form)
    }

    /**
     * POST a form-urlencoded body to Keycloak's /token endpoint.
     * OIDC requires application/x-www-form-urlencoded; JSON is rejected with 415.
     */
    private async fetchToken(form: URLSearchParams): Promise<TokenResponse> {
        const response = await fetch(this.tokenEndpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: form.toString(),
        })
        const payload = (await response.json()) as TokenResponse | KeycloakErrorPayload
        if (!response.ok) {
            throw new BadRequestException(
                `Keycloak token request failed: ${response.status} ${JSON.stringify(payload)}`,
            )
        }
        return payload as TokenResponse
    }
}
