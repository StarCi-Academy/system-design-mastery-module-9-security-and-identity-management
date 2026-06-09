import { Injectable, Logger, OnModuleInit } from "@nestjs/common"
import axios from "axios"

/**
 * Ensures the KEK exists in Vault Transit on boot. Idempotent: creating a key that
 * already exists is a no-op in Vault, so this is safe to run on every restart.
 */
@Injectable()
export class TransitBootstrap implements OnModuleInit {
    private readonly logger = new Logger(TransitBootstrap.name)

    async onModuleInit(): Promise<void> {
        const vaultAddr = process.env.VAULT_ADDR ?? "http://localhost:8200"
        const vaultToken = process.env.VAULT_TOKEN ?? "root"
        const keyName = process.env.KEK_NAME ?? "app-kek"
        const headers = { "X-Vault-Token": vaultToken }

        // Enable the transit secrets engine (ignore "already mounted").
        try {
            await axios.post(
                `${vaultAddr}/v1/sys/mounts/transit`,
                { type: "transit" },
                { headers },
            )
            this.logger.log("Transit engine enabled.")
        } catch (err: any) {
            if (err?.response?.status !== 400) {
                throw err
            }
        }

        // Create the KEK (aes256-gcm96). Re-creating an existing key is a no-op.
        await axios.post(
            `${vaultAddr}/v1/transit/keys/${keyName}`,
            { type: "aes256-gcm96" },
            { headers },
        )
        this.logger.log(`KEK '${keyName}' ready in Vault Transit.`)
    }
}
