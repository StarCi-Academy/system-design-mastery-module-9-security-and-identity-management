import { Injectable } from "@nestjs/common"
import { randomBytes, createCipheriv, createDecipheriv } from "crypto"
import { TransitService } from "../transit/transit.service"

export interface EncryptedEnvelope {
    wrappedDek: string // Vault Transit "vault:vN:..." blob — the DEK encrypted by the KEK.
    iv: string // base64 12-byte GCM nonce.
    authTag: string // base64 16-byte GCM authentication tag.
    ciphertext: string // base64 AES-256-GCM ciphertext of the plaintext.
}

/**
 * EnvelopeService implements the two-tier envelope scheme:
 *   data ── encrypted by ──▶ DEK (per-record, AES-256-GCM, generated locally)
 *   DEK  ── wrapped by ────▶ KEK (lives only in Vault Transit)
 * Bulk data never touches Vault; only the tiny 32-byte DEK is wrapped/unwrapped.
 */
@Injectable()
export class EnvelopeService {
    /** Generate a fresh DEK, AES-GCM encrypt the data, then wrap the DEK with the KEK. */
    async encrypt(plaintext: string): Promise<EncryptedEnvelope> {
        // 1. Generate a brand-new 256-bit DEK for THIS record only.
        const dek = randomBytes(32)
        const iv = randomBytes(12)

        // 2. Encrypt the bulk data locally with the DEK — Vault never sees the plaintext.
        const cipher = createCipheriv("aes-256-gcm", dek, iv)
        const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])
        const authTag = cipher.getAuthTag()

        // 3. Wrap the DEK with the KEK inside Vault, then throw the raw DEK away.
        const wrappedDek = await TransitService.wrapDek(dek)
        dek.fill(0)

        return {
            wrappedDek,
            iv: iv.toString("base64"),
            authTag: authTag.toString("base64"),
            ciphertext: ciphertext.toString("base64"),
        }
    }

    /** Unwrap the DEK via the KEK, then AES-GCM decrypt the bulk data. */
    async decrypt(env: EncryptedEnvelope): Promise<string> {
        // 1. Ask Vault to unwrap the DEK (works across KEK versions after rotation).
        const dek = await TransitService.unwrapDek(env.wrappedDek)

        // 2. Decrypt locally with the recovered DEK.
        const decipher = createDecipheriv("aes-256-gcm", dek, Buffer.from(env.iv, "base64"))
        decipher.setAuthTag(Buffer.from(env.authTag, "base64"))
        const plaintext = Buffer.concat([
            decipher.update(Buffer.from(env.ciphertext, "base64")),
            decipher.final(),
        ])
        dek.fill(0)
        return plaintext.toString("utf8")
    }
}
