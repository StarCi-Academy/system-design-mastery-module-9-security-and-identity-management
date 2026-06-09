/**
 * Node entry — bootstrap the Nest app and listen on PORT (default 3000).
 */
import {
    ValidationPipe,
} from "@nestjs/common"
import {
    NestFactory,
} from "@nestjs/core"
import {
    AppModule,
} from "./app.module"

async function bootstrap(): Promise<void> {
    const app = await NestFactory.create(AppModule)
    app.useGlobalPipes(new ValidationPipe({
        whitelist: true,
        forbidUnknownValues: false,
    }))
    const port = Number(process.env.PORT ?? 3000)
    // Bind 0.0.0.0 so the service is reachable from outside the container.
    await app.listen(port, "0.0.0.0")
}

void bootstrap()
