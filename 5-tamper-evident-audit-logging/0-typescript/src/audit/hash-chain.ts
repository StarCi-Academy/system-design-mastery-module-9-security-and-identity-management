import { createHash } from "crypto"

// The 64-zero genesis prevHash anchors the first entry — there is no row before index 0.
export const GENESIS_PREV_HASH = "0".repeat(64)

// Canonical serialization MUST be byte-identical across all 4 languages, otherwise
// the same logical event would hash differently. Fields are joined with a delimiter
// that cannot appear inside the values, in a fixed order.
export function computeEntryHash(
    index: number,
    prevHash: string,
    actor: string,
    action: string,
    target: string,
    timestamp: string,
): string {
    const payload = [index, prevHash, actor, action, target, timestamp].join("|")
    return createHash("sha256").update(payload, "utf8").digest("hex")
}
