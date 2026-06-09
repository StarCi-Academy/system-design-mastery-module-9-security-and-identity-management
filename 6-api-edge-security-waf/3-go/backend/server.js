// Minimal backend echo service — trusts that the WAF gateway already filtered
// the traffic. It simply reflects the JSON payload back so the lab can observe
// that clean requests traverse gateway -> backend end-to-end.
const http = require("http")

const PORT = process.env.PORT || 4000

const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/echo") {
        let raw = ""
        req.on("data", (chunk) => (raw += chunk))
        req.on("end", () => {
            let payload = {}
            try {
                payload = raw ? JSON.parse(raw) : {}
            } catch {
                payload = { raw }
            }
            res.writeHead(200, { "Content-Type": "application/json" })
            res.end(JSON.stringify({ received: payload, backend: "echo-service" }))
        })
        return
    }
    res.writeHead(404, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ error: "not found" }))
})

server.listen(PORT, () => console.log(`backend echo-service listening on :${PORT}`))
