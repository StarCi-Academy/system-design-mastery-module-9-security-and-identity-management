import { Injectable, NestMiddleware, Logger } from "@nestjs/common"
import { Request, Response, NextFunction } from "express"
import { inspectPayload, inspectValue } from "./rules"

// WAF middleware — the API-edge filter. It runs BEFORE any route handler and
// inspects the query string, headers, and JSON body. A malicious payload is
// short-circuited with 403; a clean request is passed through to the backend.
@Injectable()
export class WafMiddleware implements NestMiddleware {
    private static readonly logger = new Logger("WAF")

    use(req: Request, res: Response, next: NextFunction): void {
        // 1. Inspect every query-string value.
        for (const value of Object.values(req.query)) {
            const hit = inspectValue(String(value))
            if (hit) return this.block(req, res, hit)
        }

        // 2. Inspect request headers that commonly carry user-controlled data.
        const headerHit =
            inspectValue(String(req.headers["x-forwarded-for"] ?? "")) ||
            inspectValue(String(req.headers["referer"] ?? ""))
        if (headerHit) return this.block(req, res, headerHit)

        // 3. Inspect the JSON body recursively (every leaf string value).
        const bodyHit = inspectPayload(req.body)
        if (bodyHit) return this.block(req, res, bodyHit)

        // Clean request — let it reach the route handler / backend proxy.
        next()
    }

    private block(req: Request, res: Response, rule: string): void {
        WafMiddleware.logger.warn(`BLOCKED ${req.method} ${req.path} rule=${rule}`)
        // Uniform 403 contract — never echo the offending payload back.
        res.status(403).json({ status: "blocked", rule })
    }
}
