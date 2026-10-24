import { Injectable, UnauthorizedException } from "@nestjs/common"
import { PassportStrategy } from "@nestjs/passport"
import { ExtractJwt, Strategy } from "passport-jwt"
import { ConfigService } from "@nestjs/config"

import { JwtAccessPayload } from "../interfaces/jwt-payload.interface"
import { messagesHelper } from "../../helpers/messages.helper"

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, "jwt") {
    constructor(readonly configService: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: configService.getOrThrow<string>("JWT_PRIVATE_KEY"),
        })
    }

    validate(payload: JwtAccessPayload) {
        // O refresh token é assinado com o mesmo segredo: só access tokens podem ser aceitos aqui.
        if (payload.type !== "access") {
            throw new UnauthorizedException(messagesHelper.INVALID_AUTHORIZATION_TOKEN)
        }

        return {
            id: payload.sub,
            email: payload.email,
            role: payload.role,
        }
    }
}
