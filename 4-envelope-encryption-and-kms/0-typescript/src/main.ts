import { NestFactory } from "@nestjs/core"
import { AppModule } from "./app.module"

async function bootstrap() {
    // TransitBootstrap (onModuleInit) ensures the KEK exists before the port opens.
    const app = await NestFactory.create(AppModule)
    const port = parseInt(process.env.PORT ?? "3000", 10)
    await app.listen(port)
}

void bootstrap()
