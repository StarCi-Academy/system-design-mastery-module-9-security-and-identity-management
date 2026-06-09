/**
 * Shared types for Keycloak authentication.
 */

/** Response from Keycloak token endpoint (OIDC token response). */
export type TokenResponse = {
    access_token: string
    expires_in: number
    refresh_expires_in?: number
    refresh_token?: string
    token_type: string
    id_token?: string
    scope?: string
}

/** Keycloak error payload from the token endpoint. */
export type KeycloakErrorPayload = {
    error?: string
    error_description?: string
}

/** Health probe response. */
export type HealthResponse = {
    status: string
    message: string
    endpoints: Record<string, string>
}

/** Decoded JWT access token payload — only the fields the lab reads. */
export type KeycloakUser = {
    sub?: string
    preferred_username?: string
    email?: string
}
