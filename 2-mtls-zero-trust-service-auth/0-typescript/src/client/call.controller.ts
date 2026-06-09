import { Controller, Get, HttpException, HttpStatus } from "@nestjs/common"
import { TlsClientService } from "./tls-client.service"

// service-a's HTTP surface. /call presents a valid client cert (authenticated 200);
// /call-no-cert presents none, so service-b rejects the handshake and we surface 502.
@Controller()
export class CallController {
    constructor(private readonly tls: TlsClientService) {}

    @Get("call")
    async call() {
        // Returns service-b's body verbatim: { status: "ok", caller, authenticated: true }.
        return this.tls.callSecure()
    }

    @Get("call-no-cert")
    async callNoCert() {
        try {
            await this.tls.callWithoutCert()
            // If we get here the server failed to enforce mTLS — should never happen.
            throw new HttpException(
                { status: "unexpected", authenticated: false },
                HttpStatus.INTERNAL_SERVER_ERROR,
            )
        } catch (err) {
            // Handshake aborted by service-b — this is the EXPECTED zero-trust outcome.
            throw new HttpException(
                {
                    status: "rejected",
                    authenticated: false,
                    reason: err instanceof Error ? err.message : "handshake failed",
                },
                HttpStatus.BAD_GATEWAY,
            )
        }
    }
}
