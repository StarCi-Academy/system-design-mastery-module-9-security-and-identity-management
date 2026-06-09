import { Injectable } from "@nestjs/common"
import { InjectRepository } from "@nestjs/typeorm"
import { DataSource, Repository } from "typeorm"
import { AuditEvent } from "../entities/audit-event.entity"
import { computeEntryHash, GENESIS_PREV_HASH } from "./hash-chain"

export interface AppendResult {
    index: number
    prevHash: string
    entryHash: string
}

export type VerifyResult =
    | { valid: true; count: number }
    | { valid: false; brokenIndex: number; count: number }

@Injectable()
export class AuditService {
    constructor(
        @InjectRepository(AuditEvent)
        private readonly repo: Repository<AuditEvent>,
        private readonly dataSource: DataSource,
    ) {}

    // Append is serialized in a transaction so two concurrent writers cannot read the
    // same tail and fork the chain. We read the current last row, derive prevHash from
    // its entryHash, then compute and insert the new entry.
    async append(actor: string, action: string, target: string): Promise<AppendResult> {
        return this.dataSource.transaction(async (manager) => {
            const repo = manager.getRepository(AuditEvent)
            const last = await repo
                .createQueryBuilder("e")
                .orderBy("e.index", "DESC")
                .setLock("pessimistic_write")
                .getOne()

            const index = last ? last.index + 1 : 0
            const prevHash = last ? last.entryHash : GENESIS_PREV_HASH
            const timestamp = Date.now().toString()
            const entryHash = computeEntryHash(index, prevHash, actor, action, target, timestamp)

            await repo.insert({ index, actor, action, target, timestamp, prevHash, entryHash })
            return { index, prevHash, entryHash }
        })
    }

    // Verify walks the whole chain in order. For each row it recomputes the hash from the
    // stored fields and checks two invariants: the recomputed hash equals the stored
    // entryHash (row integrity), and prevHash equals the previous row's entryHash (linkage).
    // The first row that violates either is the brokenIndex.
    async verify(): Promise<VerifyResult> {
        const rows = await this.repo.find({ order: { index: "ASC" } })
        let expectedPrev = GENESIS_PREV_HASH
        for (const row of rows) {
            const recomputed = computeEntryHash(
                row.index,
                row.prevHash,
                row.actor,
                row.action,
                row.target,
                row.timestamp,
            )
            if (row.prevHash !== expectedPrev || recomputed !== row.entryHash) {
                return { valid: false, brokenIndex: row.index, count: rows.length }
            }
            expectedPrev = row.entryHash
        }
        return { valid: true, count: rows.length }
    }
}
