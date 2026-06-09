import { Module, NestModule, MiddlewareConsumer } from "@nestjs/common"
import { EchoController } from "./echo.controller"
import { WafMiddleware } from "./waf/waf.middleware"

@Module({
    controllers: [EchoController],
})
export class AppModule implements NestModule {
    configure(consumer: MiddlewareConsumer): void {
        // Apply the WAF filter to EVERY route — it is the API-edge gate.
        consumer.apply(WafMiddleware).forRoutes("*")
    }
}
