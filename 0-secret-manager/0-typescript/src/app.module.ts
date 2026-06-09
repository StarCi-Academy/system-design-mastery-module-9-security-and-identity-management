import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { User } from "./entities/user.entity"
import { UsersModule } from "./users/users.module"
import { VaultService } from "./vault/vault.service"

@Module({
    imports: [
        UsersModule,
        TypeOrmModule.forRootAsync({
            useFactory: async () => {
                // Await the runtime Vault fetch BEFORE materializing TypeORM options.
                const dbPassword = await VaultService.fetchDatabasePassword()
                return {
                    type: "postgres" as const,
                    host: process.env.DB_HOST ?? "localhost",
                    port: parseInt(process.env.DB_PORT ?? "5432", 10),
                    username: process.env.DB_USER ?? "admin",
                    password: dbPassword,
                    database: process.env.DB_NAME ?? "userdb",
                    entities: [User],
                    synchronize: true, // Lab only — never in production.
                }
            },
        }),
    ],
    providers: [VaultService],
})
export class AppModule {}
