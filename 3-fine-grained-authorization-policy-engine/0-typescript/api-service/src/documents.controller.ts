import {
    Controller,
    ForbiddenException,
    Get,
    Headers,
    NotFoundException,
    Param,
} from "@nestjs/common"
import { OpaService } from "./opa.service"
import { RESOURCES } from "./resources"
import { UserContext } from "./types"

/**
 * DocumentsController is the authz middleware: it extracts identity from request
 * headers, looks up the resource, asks OPA for a decision, and translates that
 * decision into HTTP 200 (allow) or HTTP 403 (deny). It contains NO policy logic.
 */
@Controller("documents")
export class DocumentsController {
    constructor(private readonly opa: OpaService) {}

    /**
     * Enforce access control on a document action.
     * Reads identity from `x-user-*` headers, builds the OPA input, and
     * throws ForbiddenException when OPA denies the request.
     *
     * @param id         - Document resource id (e.g. "report-finance").
     * @param action     - Attempted action: read | write | delete.
     * @param userId     - Value of `x-user-id` header.
     * @param roles      - Comma-separated roles from `x-user-roles` header.
     * @param department - Department from `x-user-department` header.
     * @param clearance  - Numeric clearance from `x-user-clearance` header.
     * @returns The allow decision with resource id and action echoed back.
     */
    // GET /documents/:id/:action — :action is read | write | delete.
    @Get(":id/:action")
    async access(
        @Param("id") id: string,
        @Param("action") action: string,
        @Headers("x-user-id") userId: string,
        @Headers("x-user-roles") roles: string,
        @Headers("x-user-department") department: string,
        @Headers("x-user-clearance") clearance: string,
    ): Promise<Record<string, unknown>> {
        // Reject unknown resources before even calling OPA to keep the decision
        // scoped to resources we know about.
        const resource = RESOURCES[id]
        if (!resource) {
            throw new NotFoundException({ status: "error", message: `Unknown resource ${id}` })
        }

        // Build the identity context from headers (a real app would read a JWT).
        // Coerce clearance to a number so the Rego >= predicate works correctly.
        const user: UserContext = {
            id: userId ?? "",
            roles: roles ? roles.split(",").map((r) => r.trim()) : [],
            department: department ?? "",
            clearance: clearance ? Number(clearance) : 0,
        }

        // Delegate the decision entirely to OPA — the controller never inspects
        // roles or attributes itself.
        const decision = await this.opa.evaluate({ user, action, resource })

        if (!decision.allow) {
            // OPA denied — surface the policy reason with HTTP 403 so the caller
            // learns which predicate failed without the app encoding any policy.
            throw new ForbiddenException({
                status: "deny",
                allowed: false,
                reason: decision.reason,
            })
        }

        // OPA allowed — echo back the decision for observability.
        return {
            status: "allow",
            allowed: true,
            reason: decision.reason,
            resource: resource.id,
            action,
        }
    }
}
