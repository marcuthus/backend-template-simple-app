import { Injectable, UnauthorizedException } from "@nestjs/common"
import { plainToInstance } from "class-transformer"
import { PassportStrategy } from "@nestjs/passport"
import { ExtractJwt, Strategy } from "passport-jwt"
import { validateSync } from "class-validator"
import { ConfigService } from "@nestjs/config"

import { JwtRefreshTokenUser } from "../interfaces/jwt-refresh-token-user.interface"
import { JwtRefreshPayload } from "../interfaces/jwt-payload.interface"
import { JwtRefreshPayloadDto } from "../dto/jwt-refresh-payload.dto"
import { messagesHelper } from "../../helpers/messages.helper"

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(Strategy, "jwt-refresh-token") {
    constructor(readonly configService: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromBodyField("refreshToken"),
            secretOrKey: configService.getOrThrow<string>("JWT_PRIVATE_KEY"),
        })
    }

    validate(payload: JwtRefreshPayload): JwtRefreshTokenUser {
        const dto = plainToInstance(JwtRefreshPayloadDto, payload)
        const errors = validateSync(dto)

        if (errors.length > 0) {
            throw new UnauthorizedException(messagesHelper.INVALID_AUTHORIZATION_TOKEN)
        }

        return {
            id: payload.sub,
        }
    }
}
