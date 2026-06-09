import { Column, Entity, PrimaryColumn } from "typeorm"

// One row per audit event. `index` is the position in the chain (0 = genesis).
// `prevHash` links to the previous row's `entryHash`; `entryHash` is the sha256
// of this row's canonical fields. Any edit to a stored row breaks the chain.
@Entity("audit_events")
export class AuditEvent {
    @PrimaryColumn({ type: "int" })
    index: number

    @Column({ type: "varchar" })
    actor: string

    @Column({ type: "varchar" })
    action: string

    @Column({ type: "varchar" })
    target: string

    @Column({ type: "bigint" })
    timestamp: string

    @Column({ type: "varchar", length: 64 })
    prevHash: string

    @Column({ type: "varchar", length: 64 })
    entryHash: string
}
