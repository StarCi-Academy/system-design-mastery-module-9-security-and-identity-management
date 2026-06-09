import { Controller, Post, Get, Body, HttpCode } from "@nestjs/common"
import axios from "axios"

// EchoController — the gateway route. Requests that survive the WAF middleware
// are forwarded to the BACKEND echo service, proving clean traffic passes
// end-to-end. The gateway itself never trusts the payload; the WAF already
// vetted it before this handler runs.
@Controller()
export class EchoController {
    private readonly backendUrl = process.env.BACKEND_URL ?? "http://localhost:4000"

    @Get("healthz")
    health(): { status: string } {
        return { status: "ok" }
    }

    @Post("api/echo")
    @HttpCode(200) // Clean requests return 200 (uniform contract across all tracks).
    async echo(@Body() body: Record<string, unknown>): Promise<unknown> {
        // Forward the vetted payload to the backend and relay its response.
        const response = await axios.post(`${this.backendUrl}/echo`, body)
        return { status: "allowed", echo: response.data }
    }
}
