import { Injectable } from "@nestjs/common"
import { ConfigService } from "@nestjs/config"
import axios from "axios"
import { OpaInput, OpaResult } from "./types"

/**
 * OpaService externalizes every authorization decision to Open Policy Agent.
 * The app holds NO policy logic itself — it only builds the input document and
 * asks OPA's HTTP decision API whether the action is allowed.
 */
@Injectable()
export class OpaService {
    /** Full URL to the OPA data path that maps to package app.authz. */
    private readonly opaUrl: string

    constructor(private readonly config: ConfigService) {
        // Read the OPA base URL from the environment; fall back to the docker-network
        // hostname "opa" so the service works out of the box with compose.yaml.
        const base = this.config.get<string>("OPA_BASE_URL", "http://opa:8181")
        // Append the data path: /v1/data/app/authz mirrors the Rego package name.
        this.opaUrl = `${base}/v1/data/app/authz`
    }

    /**
     * Ask OPA whether the given input should be allowed.
     * Sends `{ input }` to OPA's data API and returns the decision document.
     *
     * @param input - The context document (user + action + resource) for this request.
     * @returns The allow boolean and the policy-supplied reason string.
     * @throws When OPA is unreachable or returned no decision document.
     */
    async evaluate(input: OpaInput): Promise<{ allow: boolean; reason: string }> {
        // Wrap in { input: ... } — OPA binds the value to the `input` document in Rego.
        const response = await axios.post<OpaResult>(this.opaUrl, { input })
        const result = response.data.result
        if (!result) {
            // No decision document means the policy package failed to load.
            throw new Error("OPA returned no decision for data.app.authz")
        }
        // Return only the two fields the controller needs; leave OPA internals behind.
        return { allow: result.allow, reason: result.reason }
    }
}
