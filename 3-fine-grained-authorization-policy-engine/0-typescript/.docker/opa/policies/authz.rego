# Fine-grained authorization policy for the demo API.
# Demonstrates three models in one decision: RBAC, ABAC, and ReBAC.
#
# Decision entrypoint: data.app.authz.allow (a single boolean).
# Input contract (sent by the app on every request):
#   {
#     "user":     { "id": "u1", "roles": ["admin"], "department": "finance", "clearance": 3 },
#     "action":   "read" | "write" | "delete",
#     "resource": { "type": "report", "owner": "u1", "department": "finance", "sensitivity": 2 }
#   }
package app.authz

import rego.v1

# Default deny: nothing is allowed unless an explicit rule below grants it.
default allow := false

# ---------------------------------------------------------------------------
# RBAC — Role-Based Access Control.
# An "admin" role may perform any action on any resource.
# ---------------------------------------------------------------------------
allow if {
	"admin" in input.user.roles
}

# ---------------------------------------------------------------------------
# ReBAC — Relationship-Based Access Control.
# A user may read or write a resource they OWN, regardless of their role.
# The relationship checked is: resource.owner == user.id.
# ---------------------------------------------------------------------------
allow if {
	input.action in {"read", "write"}
	input.resource.owner == input.user.id
}

# ---------------------------------------------------------------------------
# ABAC — Attribute-Based Access Control.
# A user may READ a resource when BOTH attribute predicates hold:
#   1. same department  (user.department == resource.department)
#   2. clearance covers sensitivity (user.clearance >= resource.sensitivity)
# ---------------------------------------------------------------------------
allow if {
	input.action == "read"
	input.user.department == input.resource.department
	input.user.clearance >= input.resource.sensitivity
}

# Machine-readable reason for the decision (used by the app for the response body).
reason := "rbac: admin role grants all actions" if {
	"admin" in input.user.roles
}

reason := "rebac: user owns the resource" if {
	not "admin" in input.user.roles
	input.action in {"read", "write"}
	input.resource.owner == input.user.id
}

reason := "abac: same department and sufficient clearance" if {
	not "admin" in input.user.roles
	input.resource.owner != input.user.id
	input.action == "read"
	input.user.department == input.resource.department
	input.user.clearance >= input.resource.sensitivity
}

reason := "denied: no policy rule grants this action" if {
	not allow
}
