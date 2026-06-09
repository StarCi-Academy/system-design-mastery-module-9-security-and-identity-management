import { readFileSync } from "node:fs"
import * as https from "node:https"
import type { TLSSocket } from "node:tls"

// service-b — the mTLS server. It trusts ONLY peers whose client cert was signed
// by the internal CA. requestCert + rejectUnauthorized = zero-trust at the TLS layer:
// no valid client cert means the handshake is aborted before any HTTP is read.
const CERTS_DIR = process.env.CERTS_DIR ?? "/certs"
const PORT = parseInt(process.env.PORT ?? "8443", 10)

const options: https.ServerOptions = {
    key: readFileSync(`${CERTS_DIR}/server.key`),
    cert: readFileSync(`${CERTS_DIR}/server.crt`),
    // The CA bundle used to VERIFY the client certificate presented in the handshake.
    ca: readFileSync(`${CERTS_DIR}/ca.crt`),
    requestCert: true, // Ask every client to present a certificate.
    rejectUnauthorized: true, // Abort the handshake if that cert is missing or untrusted.
}

const server = https.createServer(options, (req, res) => {
    const socket = req.socket as TLSSocket
    // Reaching this handler already proves the client cert passed CA verification.
    const cert = socket.getPeerCertificate()
    const caller = cert?.subject?.CN ?? "unknown"

    if (req.url === "/secure" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" })
        res.end(JSON.stringify({ status: "ok", caller, authenticated: true }))
        return
    }
    res.writeHead(404, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ status: "not_found" }))
})

server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[service-b] mTLS server listening on :${PORT} (requestCert + rejectUnauthorized)`)
})
