import { Injectable, Logger } from "@nestjs/common"
import axios from "axios"

// VaultService — reads DB_PASSWORD from HashiCorp Vault (KV v2) at runtime, not from a static env var.
@Injectable()
export class VaultService {
    private static readonly logger = new Logger(VaultService.name)

    static async fetchDatabasePassword(): Promise<string> {
        const vaultAddr = process.env.VAULT_ADDR ?? "http://localhost:8200"
        const vaultToken = process.env.VAULT_TOKEN ?? "root"

        this.logger.log(`Fetching secret from Vault at ${vaultAddr}/v1/secret/data/my-app...`)

        // Read the secret over Vault's HTTP API at runtime, not from a static env var.
        const response = await axios.get(`${vaultAddr}/v1/secret/data/my-app`, {
            headers: { "X-Vault-Token": vaultToken },
        })

        // KV v2 wraps the payload twice: data.data = values, data.metadata = version.
        const password = response.data?.data?.data?.DB_PASSWORD
        if (!password) {
            throw new Error("DB_PASSWORD not found in Vault secret.")
        }

        this.logger.log("Successfully retrieved DB_PASSWORD from Vault.")
        return password
    }
}
