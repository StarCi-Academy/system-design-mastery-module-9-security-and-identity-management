import { Column, Entity, PrimaryGeneratedColumn } from "typeorm"

/**
 * A SecureRecord stores ONLY ciphertext and the wrapped DEK — never the plaintext
 * and never the raw DEK. Even a full database dump is useless without the KEK in Vault.
 */
@Entity("secure_records")
export class SecureRecord {
    @PrimaryGeneratedColumn()
    id: number

    @Column({ name: "wrapped_dek", type: "text" })
    wrappedDek: string

    @Column({ type: "text" })
    iv: string

    @Column({ name: "auth_tag", type: "text" })
    authTag: string

    @Column({ type: "text" })
    ciphertext: string
}
