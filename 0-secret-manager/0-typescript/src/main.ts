import { NestFactory } from "@nestjs/core"
import { AppModule } from "./app.module"

async function bootstrap() {
    // The Vault fetch runs inside AppModule init (TypeOrmModule.forRootAsync) before the port opens.
    const app = await NestFactory.create(AppModule)
    const port = parseInt(process.env.PORT ?? "3000", 10)
    // Bind 0.0.0.0 so the container is reachable from the host (default 127.0.0.1 refuses host curl).
    await app.listen(port, "0.0.0.0")
}

void bootstrap()
