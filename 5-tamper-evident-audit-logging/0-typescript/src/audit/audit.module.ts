import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { AuditEvent } from "../entities/audit-event.entity"
import { AuditController } from "./audit.controller"
import { AuditService } from "./audit.service"

@Module({
    imports: [TypeOrmModule.forFeature([AuditEvent])],
    controllers: [AuditController],
    providers: [AuditService],
})
export class AuditModule {}
