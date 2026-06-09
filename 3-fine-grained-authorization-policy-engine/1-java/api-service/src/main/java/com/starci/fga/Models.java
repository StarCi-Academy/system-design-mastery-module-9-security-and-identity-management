package com.starci.fga;

import java.util.List;
import java.util.Map;

/**
 * Value types and the in-memory resource catalog describing the OPA decision contract.
 * All records are package-private — only the controllers and service use them directly.
 */
final class Models {

    /** Prevent instantiation; this is a pure namespace class. */
    private Models() {}

    /**
     * Identity attributes extracted from request headers.
     *
     * @param id         Unique user identifier (e.g. "alice").
     * @param roles      Role names carried by the user (e.g. ["admin"]).
     * @param department Organisational department the user belongs to.
     * @param clearance  Numeric security clearance — must be >= resource sensitivity for ABAC read.
     */
    record UserContext(String id, List<String> roles, String department, int clearance) {}

    /**
     * A protected resource stored in the in-memory catalog.
     *
     * @param id          Unique resource identifier (e.g. "report-finance").
     * @param type        Resource category (e.g. "report") — informational only.
     * @param owner       User-id of the principal who owns the resource (used by ReBAC).
     * @param department  Organisational department the resource belongs to (used by ABAC).
     * @param sensitivity Sensitivity level — the user's clearance must be >= this for ABAC.
     */
    record Resource(String id, String type, String owner, String department, int sensitivity) {}

    /**
     * The exact JSON document POSTed to OPA as the {@code "input"} field.
     *
     * @param user     Identity context for the requesting principal.
     * @param action   Action being attempted: read | write | delete.
     * @param resource Resource being acted upon.
     */
    record OpaInput(UserContext user, String action, Resource resource) {}

    /**
     * In-memory resource catalog, identical across all language tracks.
     * Keyed by resource id so the controller can look up a resource in O(1).
     */
    static final Map<String, Resource> RESOURCES = Map.of(
            // finance report — owned by alice, sensitivity 2 (medium)
            "report-finance", new Resource("report-finance", "report", "alice", "finance", 2),
            // engineering report — owned by bob, sensitivity 3 (high)
            "report-eng", new Resource("report-eng", "report", "bob", "engineering", 3));
}
