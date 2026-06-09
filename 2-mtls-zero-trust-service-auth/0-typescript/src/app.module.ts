import { Module } from "@nestjs/common"
import { CallController } from "./client/call.controller"
import { TlsClientService } from "./client/tls-client.service"

@Module({
    controllers: [CallController],
    providers: [TlsClientService],
})
export class AppModule {}
