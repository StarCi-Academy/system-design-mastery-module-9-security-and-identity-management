import { NestFactory } from "@nestjs/core"
import { Logger } from "@nestjs/common"
import { AppModule } from "./app.module"

async function bootstrap(): Promise<void> {
    const app = await NestFactory.create(AppModule)
    const port = parseInt(process.env.PORT ?? "3000", 10)
    await app.listen(port)
    new Logger("Bootstrap").log(`WAF gateway listening on :${port}`)
}

void bootstrap()
