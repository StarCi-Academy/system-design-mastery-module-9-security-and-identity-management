import { readFileSync } from "node:fs"
import * as https from "node:https"
import { Injectable, Logger } from "@nestjs/common"

export interface SecureResponse {
    status: string
    caller?: string
    authenticated?: boolean
}

// TlsClientService — service-a's outbound mTLS client toward service-b.
// It loads its OWN client cert/key (signed by the internal CA) plus the CA bundle
// used to verify service-b's server cert. This is mutual: both sides verify each other.
@Injectable()
export class TlsClientService {
    private readonly logger = new Logger(TlsClientService.name)
    private readonly certsDir = process.env.CERTS_DIR ?? "/certs"
    private readonly targetHost = process.env.SERVICE_B_HOST ?? "service-b"
    private readonly targetPort = parseInt(process.env.SERVICE_B_PORT ?? "8443", 10)

    // Authenticated call: present the client certificate during the TLS handshake.
    async callSecure(): Promise<SecureResponse> {
        const agent = new https.Agent({
            ca: readFileSync(`${this.certsDir}/ca.crt`),
            cert: readFileSync(`${this.certsDir}/client.crt`),
            key: readFileSync(`${this.certsDir}/client.key`),
        })
        return this.get(agent)
    }

    // Untrusted call: NO client certificate is presented. service-b must reject the
    // handshake, proving zero-trust — internal traffic without a valid cert is denied.
    async callWithoutCert(): Promise<SecureResponse> {
        const agent = new https.Agent({
            ca: readFileSync(`${this.certsDir}/ca.crt`),
            // No cert/key on purpose.
        })
        return this.get(agent)
    }

    private get(agent: https.Agent): Promise<SecureResponse> {
        return new Promise((resolve, reject) => {
            const req = https.request(
                {
                    host: this.targetHost,
                    port: this.targetPort,
                    path: "/secure",
                    method: "GET",
                    agent,
                    servername: "service-b", // Match the server cert SAN/CN.
                },
                (res) => {
                    let body = ""
                    res.on("data", (chunk) => (body += chunk))
                    res.on("end", () => {
                        try {
                            resolve(JSON.parse(body) as SecureResponse)
                        } catch {
                            reject(new Error(`Bad response body: ${body}`))
                        }
                    })
                },
            )
            req.on("error", (err) => {
                this.logger.warn(`mTLS call rejected: ${err.message}`)
                reject(err)
            })
            req.end()
        })
    }
}
