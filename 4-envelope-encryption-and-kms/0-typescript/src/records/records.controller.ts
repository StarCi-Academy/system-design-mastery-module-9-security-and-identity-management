import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpException,
    HttpStatus,
    Logger,
    Param,
    Post,
} from "@nestjs/common"
import { InjectRepository } from "@nestjs/typeorm"
import { Repository } from "typeorm"
import { SecureRecord } from "../entities/record.entity"
import { EnvelopeService } from "../crypto/envelope.service"
import { TransitService } from "../transit/transit.service"

@Controller()
export class RecordsController {
    private readonly logger = new Logger(RecordsController.name)

    constructor(
        @InjectRepository(SecureRecord)
        private readonly repo: Repository<SecureRecord>,
        private readonly envelope: EnvelopeService,
    ) {}

    /** POST /records — encrypt the plaintext and store ciphertext + wrapped DEK. */
    @Post("records")
    @HttpCode(HttpStatus.CREATED)
    async create(@Body() body: { plaintext: string }): Promise<{ id: number; status: string }> {
        const env = await this.envelope.encrypt(body.plaintext)
        const saved = await this.repo.save(this.repo.create(env))
        this.logger.log(`Record ${saved.id} encrypted (DEK wrapped by KEK).`)
        return { id: saved.id, status: "encrypted" }
    }

    /** GET /records/:id — unwrap the DEK, decrypt, return the plaintext. */
    @Get("records/:id")
    async findOne(@Param("id") id: string): Promise<{ id: number; plaintext: string }> {
        const record = await this.repo.findOneBy({ id: parseInt(id, 10) })
        if (!record) {
            throw new HttpException({ status: "not_found" }, HttpStatus.NOT_FOUND)
        }
        try {
            const plaintext = await this.envelope.decrypt(record)
            return { id: record.id, plaintext }
        } catch {
            // KEK was shredded (or unreachable): the DEK can no longer be unwrapped.
            throw new HttpException({ status: "unrecoverable" }, HttpStatus.UNPROCESSABLE_ENTITY)
        }
    }

    /** POST /kek/rotate — rotate the KEK to a new version; old wrapped DEKs stay valid. */
    @Post("kek/rotate")
    @HttpCode(HttpStatus.OK)
    async rotate(): Promise<{ status: string; version: number }> {
        const version = await TransitService.rotateKek()
        this.logger.log(`KEK rotated to version ${version}.`)
        return { status: "rotated", version }
    }

    /** POST /kek/shred — crypto-shredding: delete the KEK; all records become unrecoverable. */
    @Post("kek/shred")
    @HttpCode(HttpStatus.OK)
    async shred(): Promise<{ status: string }> {
        await TransitService.shredKek()
        return { status: "shredded" }
    }
}
