import { Resource } from "./types"

// In-memory resource catalog. In production this would be a database row; here
// it is seeded so the lesson stays focused on the OPA decision, not persistence.

/**
 * Static resource catalog keyed by resource id.
 * Both entries mirror the identities used in the §2.1.5 test flows so learners
 * can predict which Rego rule will fire before running the curl commands.
 */
export const RESOURCES: Record<string, Resource> = {
    // finance report — owned by alice, sensitivity 2 (medium)
    "report-finance": {
        id: "report-finance",
        type: "report",
        owner: "alice",          // ReBAC: alice owns this resource
        department: "finance",   // ABAC: must be in finance dept to match
        sensitivity: 2,          // ABAC: clearance >= 2 required for read
    },
    // engineering report — owned by bob, sensitivity 3 (high)
    "report-eng": {
        id: "report-eng",
        type: "report",
        owner: "bob",            // ReBAC: bob owns this resource
        department: "engineering", // ABAC: must be in engineering dept to match
        sensitivity: 3,           // ABAC: clearance >= 3 required for read
    },
}
