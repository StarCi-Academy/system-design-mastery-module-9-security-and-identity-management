import { NestFactory } from "@nestjs/core"
import { AppModule } from "./app.module"

/**
 * Bootstrap the NestJS application and bind it to all network interfaces
 * so the Docker port mapping (host → container) is reachable from outside
 * the container.
 */
async function bootstrap(): Promise<void> {
    const app = await NestFactory.create(AppModule)
    // Read PORT from the environment (set by compose.yaml); default to 3000.
    const port = Number(process.env.PORT) || 3000
    // Bind to 0.0.0.0 — without this NestJS defaults to 127.0.0.1 which is
    // unreachable from the Docker host even with a published port.
    await app.listen(port, "0.0.0.0")
    // eslint-disable-next-line no-console
    console.log(`api-service listening on port ${port}`)
}

void bootstrap()
