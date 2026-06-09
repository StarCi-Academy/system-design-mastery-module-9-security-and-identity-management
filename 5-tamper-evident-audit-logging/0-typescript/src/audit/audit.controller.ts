import { Body, Controller, Get, HttpCode, Post } from "@nestjs/common"
import { AuditService } from "./audit.service"

interface AppendDto {
    actor?: string
    action?: string
    target?: string
}

@Controller()
export class AuditController {
    constructor(private readonly auditService: AuditService) {}

    // POST /events — append one event, returning its position and the two hashes
    // so the caller can independently verify linkage.
    @Post("events")
    @HttpCode(201)
    async append(@Body() body: AppendDto) {
        const actor = body.actor ?? "unknown"
        const action = body.action ?? "unknown"
        const target = body.target ?? "unknown"
        return this.auditService.append(actor, action, target)
    }

    // GET /verify — recompute the entire chain and report OK or the first broken index.
    @Get("verify")
    async verify() {
        return this.auditService.verify()
    }
}
