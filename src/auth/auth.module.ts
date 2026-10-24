import { forwardRef, Module } from "@nestjs/common"
import { PassportModule } from "@nestjs/passport"
import { ConfigService } from "@nestjs/config"
import { JwtModule } from "@nestjs/jwt"

import type { StringValue } from "ms"

import { JwtRefreshTokenStrategy } from "./strategies/jwt-refresh-token.strategy"
import { ApiKeyStrategy } from "./strategies/api-key.strategy"
import { LocalStrategy } from "./strategies/local.strategy"
import { JwtStrategy } from "./strategies/jwt.strategy"
import { UsersModule } from "../users/users.module"
import { AuthController } from "./auth.controller"
import { AuthService } from "./auth.service"

@Module({
    imports: [
        PassportModule,
        forwardRef(() => UsersModule),
        JwtModule.registerAsync({
            useFactory: (configService: ConfigService) => ({
                // "secret" serve para assinar e verificar (HS256)
                secret: configService.getOrThrow<string>("JWT_PRIVATE_KEY"),
                signOptions: { expiresIn: configService.getOrThrow<StringValue>("ACCESS_SIGN_EXPIRES_IN") },
            }),
            inject: [ConfigService],
        }),
    ],
    // JwtRefreshTokenStrategy não estava registrada: POST /auth/refresh-token sempre falhava
    providers: [AuthService, LocalStrategy, JwtStrategy, ApiKeyStrategy, JwtRefreshTokenStrategy],
    controllers: [AuthController],
    exports: [AuthService],
})
export class AuthModule {}
