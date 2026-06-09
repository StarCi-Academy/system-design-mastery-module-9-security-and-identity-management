import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { SecureRecord } from "./entities/record.entity"
import { RecordsModule } from "./records/records.module"
import { TransitBootstrap } from "./transit/transit.bootstrap"

@Module({
    imports: [
        TypeOrmModule.forRoot({
            type: "postgres",
            host: process.env.DB_HOST ?? "localhost",
            port: parseInt(process.env.DB_PORT ?? "5432", 10),
            username: process.env.DB_USER ?? "admin",
            password: process.env.DB_PASSWORD ?? "123456",
            database: process.env.DB_NAME ?? "vaultdb",
            entities: [SecureRecord],
            synchronize: true, // Lab only — never in production.
        }),
        RecordsModule,
    ],
    providers: [TransitBootstrap],
})
export class AppModule {}
