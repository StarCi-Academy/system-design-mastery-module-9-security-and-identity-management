// Shared types describing the OPA decision contract.

/** The identity attributes the app extracts from request headers. */
export interface UserContext {
    /** Unique user identifier (e.g. "alice"). */
    id: string
    /** Role names carried by the user (e.g. ["admin", "analyst"]). */
    roles: string[]
    /** Organisational department the user belongs to. */
    department: string
    /** Numeric security clearance level — compared against resource sensitivity. */
    clearance: number
}

/** A protected resource the app stores in memory and asks OPA about. */
export interface Resource {
    /** Unique resource identifier (e.g. "report-finance"). */
    id: string
    /** Resource category — used for display/logging only. */
    type: string
    /** User-id of the principal who created / owns the resource. */
    owner: string
    /** Organisational department the resource belongs to — matched by ABAC. */
    department: string
    /** Sensitivity level — the user's clearance must be >= this for ABAC read access. */
    sensitivity: number
}

/** The exact JSON document the app POSTs to OPA as the "input". */
export interface OpaInput {
    /** Identity context extracted from the request. */
    user: UserContext
    /** Action being attempted: read | write | delete. */
    action: string
    /** Resource being acted upon. */
    resource: Resource
}

/** OPA's response envelope for POST /v1/data/<path>. */
export interface OpaResult {
    /** Present only when OPA evaluated a complete policy document. */
    result?: {
        /** Whether the policy granted the request. */
        allow: boolean
        /** Human-readable reason returned by the Rego reason rule. */
        reason: string
    }
}
