import { Injectable, Logger } from "@nestjs/common"
import axios from "axios"

/**
 * TransitService talks to Vault's Transit secrets engine — the KMS in this lab.
 * The KEK (key encryption key) NEVER leaves Vault; we only send it the DEK to wrap,
 * and receive ciphertext back. This is "encryption as a service".
 */
@Injectable()
export class TransitService {
    private static readonly logger = new Logger(TransitService.name)
    private static readonly vaultAddr = process.env.VAULT_ADDR ?? "http://localhost:8200"
    private static readonly vaultToken = process.env.VAULT_TOKEN ?? "root"
    private static readonly keyName = process.env.KEK_NAME ?? "app-kek"

    private static headers() {
        return { "X-Vault-Token": TransitService.vaultToken }
    }

    /** Wrap a raw DEK with the KEK inside Vault. Returns Vault's "vault:v1:..." ciphertext blob. */
    static async wrapDek(rawDek: Buffer): Promise<string> {
        const url = `${TransitService.vaultAddr}/v1/transit/encrypt/${TransitService.keyName}`
        // The DEK is sent base64-encoded; the KEK that encrypts it stays in Vault.
        const response = await axios.post(
            url,
            { plaintext: rawDek.toString("base64") },
            { headers: TransitService.headers() },
        )
        const wrapped = response.data?.data?.ciphertext
        if (!wrapped) {
            throw new Error("Transit wrap returned no ciphertext.")
        }
        return wrapped
    }

    /** Unwrap a wrapped DEK back to the raw key bytes. Works across KEK versions. */
    static async unwrapDek(wrappedDek: string): Promise<Buffer> {
        const url = `${TransitService.vaultAddr}/v1/transit/decrypt/${TransitService.keyName}`
        const response = await axios.post(
            url,
            { ciphertext: wrappedDek },
            { headers: TransitService.headers() },
        )
        const plaintextB64 = response.data?.data?.plaintext
        if (!plaintextB64) {
            throw new Error("Transit unwrap returned no plaintext.")
        }
        return Buffer.from(plaintextB64, "base64")
    }

    /** Rotate the KEK to a new version. Old versions remain usable for decrypt. */
    static async rotateKek(): Promise<number> {
        const rotateUrl = `${TransitService.vaultAddr}/v1/transit/keys/${TransitService.keyName}/rotate`
        await axios.post(rotateUrl, {}, { headers: TransitService.headers() })
        const readUrl = `${TransitService.vaultAddr}/v1/transit/keys/${TransitService.keyName}`
        const read = await axios.get(readUrl, { headers: TransitService.headers() })
        return read.data?.data?.latest_version as number
    }

    /** Crypto-shredding: delete the KEK so no wrapped DEK can ever be unwrapped again. */
    static async shredKek(): Promise<void> {
        // deletion_allowed must be set on the key before it can be deleted.
        const configUrl = `${TransitService.vaultAddr}/v1/transit/keys/${TransitService.keyName}/config`
        await axios.post(
            configUrl,
            { deletion_allowed: true },
            { headers: TransitService.headers() },
        )
        const deleteUrl = `${TransitService.vaultAddr}/v1/transit/keys/${TransitService.keyName}`
        await axios.delete(deleteUrl, { headers: TransitService.headers() })
        TransitService.logger.warn(`KEK '${TransitService.keyName}' deleted — all wrapped DEKs are now unrecoverable.`)
    }
}
