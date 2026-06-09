import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { SecureRecord } from "../entities/record.entity"
import { RecordsController } from "./records.controller"
import { EnvelopeService } from "../crypto/envelope.service"

@Module({
    imports: [TypeOrmModule.forFeature([SecureRecord])],
    controllers: [RecordsController],
    providers: [EnvelopeService],
})
export class RecordsModule {}
