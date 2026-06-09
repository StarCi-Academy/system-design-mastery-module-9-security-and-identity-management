import { Controller, Get, OnModuleInit } from "@nestjs/common"
import { InjectRepository } from "@nestjs/typeorm"
import { Repository } from "typeorm"
import { User } from "../entities/user.entity"

// GET /users — seeds 2 rows once, then returns all users; proves the DB connection works.
@Controller("users")
export class UsersController implements OnModuleInit {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) {}

    async onModuleInit() {
        // Seed demo data only when the table is empty.
        const count = await this.userRepository.count()
        if (count === 0) {
            await this.userRepository.save([
                { name: "Admin StarCi" },
                { name: "Học viên VIP" },
            ])
        }
    }

    @Get()
    async findAll() {
        const users = await this.userRepository.find()
        return {
            status: "success",
            data: users,
        }
    }
}
