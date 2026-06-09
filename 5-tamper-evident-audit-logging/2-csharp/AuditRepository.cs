using Npgsql;

namespace AuditLogApi;

public record AppendResult(int Index, string PrevHash, string EntryHash);

// AuditRepository owns all chain reads/writes against PostgreSQL.
public class AuditRepository
{
    private readonly NpgsqlDataSource _dataSource;

    public AuditRepository(NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    public async Task InitSchemaAsync()
    {
        await using var cmd = _dataSource.CreateCommand(@"
            CREATE TABLE IF NOT EXISTS audit_events (
                index INT PRIMARY KEY,
                actor VARCHAR NOT NULL,
                action VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                timestamp BIGINT NOT NULL,
                prev_hash VARCHAR(64) NOT NULL,
                entry_hash VARCHAR(64) NOT NULL
            )");
        await cmd.ExecuteNonQueryAsync();
    }

    // Append is serialized in a transaction with a table lock so two concurrent writers
    // cannot read the same tail and fork the chain.
    public async Task<AppendResult> AppendAsync(string actor, string action, string target)
    {
        await using var conn = await _dataSource.OpenConnectionAsync();
        await using var tx = await conn.BeginTransactionAsync();

        await using (var lockCmd = new NpgsqlCommand("LOCK TABLE audit_events IN EXCLUSIVE MODE", conn, tx))
        {
            await lockCmd.ExecuteNonQueryAsync();
        }

        var index = 0;
        var prevHash = HashChain.GenesisPrevHash;
        await using (var lastCmd = new NpgsqlCommand(
                         "SELECT index, entry_hash FROM audit_events ORDER BY index DESC LIMIT 1", conn, tx))
        await using (var reader = await lastCmd.ExecuteReaderAsync())
        {
            if (await reader.ReadAsync())
            {
                index = reader.GetInt32(0) + 1;
                prevHash = reader.GetString(1);
            }
        }

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var entryHash = HashChain.ComputeEntryHash(index, prevHash, actor, action, target, timestamp);

        await using (var insert = new NpgsqlCommand(
                         @"INSERT INTO audit_events (index, actor, action, target, timestamp, prev_hash, entry_hash)
                           VALUES (@i,@ac,@an,@t,@ts,@p,@e)", conn, tx))
        {
            insert.Parameters.AddWithValue("i", index);
            insert.Parameters.AddWithValue("ac", actor);
            insert.Parameters.AddWithValue("an", action);
            insert.Parameters.AddWithValue("t", target);
            insert.Parameters.AddWithValue("ts", timestamp);
            insert.Parameters.AddWithValue("p", prevHash);
            insert.Parameters.AddWithValue("e", entryHash);
            await insert.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
        return new AppendResult(index, prevHash, entryHash);
    }

    // Verify walks the chain in order, recomputing each hash and checking linkage.
    public async Task<object> VerifyAsync()
    {
        await using var cmd = _dataSource.CreateCommand(
            "SELECT index, actor, action, target, timestamp, prev_hash, entry_hash FROM audit_events ORDER BY index ASC");
        await using var reader = await cmd.ExecuteReaderAsync();

        var expectedPrev = HashChain.GenesisPrevHash;
        var count = 0;
        int? brokenIndex = null;
        while (await reader.ReadAsync())
        {
            count++;
            var index = reader.GetInt32(0);
            var actor = reader.GetString(1);
            var action = reader.GetString(2);
            var target = reader.GetString(3);
            var timestamp = reader.GetInt64(4);
            var prevHash = reader.GetString(5);
            var entryHash = reader.GetString(6);

            // Record the FIRST broken row, then keep reading so count reflects the
            // whole table (the contract reports total rows, not rows-read-before-break).
            if (brokenIndex is null)
            {
                var recomputed = HashChain.ComputeEntryHash(index, prevHash, actor, action, target, timestamp);
                if (prevHash != expectedPrev || recomputed != entryHash)
                {
                    brokenIndex = index;
                }
                expectedPrev = entryHash;
            }
        }
        if (brokenIndex is not null)
        {
            return new { valid = false, brokenIndex = brokenIndex.Value, count };
        }
        return new { valid = true, count };
    }
}
