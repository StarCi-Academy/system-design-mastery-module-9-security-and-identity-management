import { Controller, Get } from "@nestjs/common"

/**
 * AppController exposes a health-check endpoint.
 * It is not gated by any OPA policy — used only to verify the service is up.
 */
@Controller()
export class AppController {
    /**
     * Liveness probe — returns HTTP 200 with `{ status: "ok" }`.
     * @returns Static status object confirming the service is running.
     */
    @Get("health")
    health(): { status: string } {
        // Always returns ok; if the service is down this handler never executes.
        return { status: "ok" }
    }
}
