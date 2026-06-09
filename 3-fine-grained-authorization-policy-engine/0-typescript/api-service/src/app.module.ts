import { Module } from "@nestjs/common"
import { ConfigModule } from "@nestjs/config"
import { AppController } from "./app.controller"
import { DocumentsController } from "./documents.controller"
import { OpaService } from "./opa.service"

/**
 * AppModule wires together the OPA service and both controllers.
 * ConfigModule is made global so OpaService can inject ConfigService
 * without each feature module importing ConfigModule separately.
 */
@Module({
    // ConfigModule.forRoot makes environment variables available app-wide via
    // ConfigService; isGlobal: true avoids re-importing it in each feature module.
    imports: [ConfigModule.forRoot({ isGlobal: true })],
    controllers: [AppController, DocumentsController],
    providers: [OpaService],
})
export class AppModule {}
