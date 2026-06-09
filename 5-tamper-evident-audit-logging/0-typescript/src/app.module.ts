import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { AuditModule } from "./audit/audit.module"
import { AuditEvent } from "./entities/audit-event.entity"

@Module({
    imports: [
        TypeOrmModule.forRoot({
            type: "postgres",
            host: process.env.DB_HOST ?? "localhost",
            port: parseInt(process.env.DB_PORT ?? "5432", 10),
            username: process.env.DB_USER ?? "admin",
            password: process.env.DB_PASSWORD ?? "123456",
            database: process.env.DB_NAME ?? "auditdb",
            entities: [AuditEvent],
            synchronize: true, // Lab only — never in production.
        }),
        AuditModule,
    ],
})
export class AppModule {}
