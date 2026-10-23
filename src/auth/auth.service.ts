import { Injectable, UnauthorizedException } from "@nestjs/common"
import { ConfigService } from "@nestjs/config"
import { JwtService } from "@nestjs/jwt"
import * as bcrypt from "bcrypt"

import type { StringValue } from "ms"

import { JwtAccessPayload, JwtRefreshPayload } from "./interfaces/jwt-payload.interface"
import { UserWithoutSensitiveInfo } from "../users/users.types"
import { messagesHelper } from "../helpers/messages.helper"
import { RefreshTokenDto } from "./dto/refresh-token.dto"
import { UsersService } from "../users/users.service"
import { User } from "../generated/prisma/client"
import { SignUpDto } from "./dto/sign-up.dto"

@Injectable()
export class AuthService {
    private readonly refreshSignExpiresIn: StringValue

    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) {
        this.refreshSignExpiresIn = configService.getOrThrow<StringValue>("REFRESH_SIGN_EXPIRES_IN")
    }

    async signIn(user: User) {
        const accessPayload = {
            sub: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            name: user.name,
            type: "access",
        } satisfies JwtAccessPayload

        const refreshPayload = {
            sub: user.id,
            type: "refresh",
        } satisfies JwtRefreshPayload

        return {
            accessToken: this.jwtService.sign(accessPayload),
            refreshToken: this.jwtService.sign(refreshPayload, {
                expiresIn: this.refreshSignExpiresIn,
            }),
        }
    }

    async signUp(signUpDto: SignUpDto) {
        return await this.usersService.create(signUpDto)
    }

    async refreshToken(userId: string, { refreshToken }: RefreshTokenDto) {
        let payload: JwtRefreshPayload

        try {
            payload = this.jwtService.verify<JwtRefreshPayload>(refreshToken)
        } catch (error) {
            throw new UnauthorizedException(messagesHelper.INVALID_AUTHORIZATION_TOKEN)
        }

        if (payload.type !== "refresh" || payload.sub !== userId) {
            throw new UnauthorizedException(messagesHelper.INVALID_AUTHORIZATION_TOKEN)
        }

        const user = await this.usersService.findOne(payload.sub)

        const accessPayload = {
            sub: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            name: user.name,
            type: "access",
        } satisfies JwtAccessPayload

        const newRefreshPayload = {
            sub: user.id,
            type: "refresh",
        } satisfies JwtRefreshPayload

        return {
            accessToken: this.jwtService.sign(accessPayload),
            refreshToken: this.jwtService.sign(newRefreshPayload, {
                expiresIn: this.refreshSignExpiresIn,
            }),
        }
    }

    async validateUser(email: string, password: string): Promise<UserWithoutSensitiveInfo | null> {
        const user = await this.usersService.safeFindOneByEmail(email)

        if (!user) {
            return null
        }

        const isValidPassword = await bcrypt.compare(password, user.password)

        if (!isValidPassword) {
            return null
        }

        const { password: _, apiKey: __, ...rest } = user

        return rest
    }

    async validateApiKey(apiKey: string) {
        const user = await this.usersService.safeFindOneByApiKey(apiKey)

        if (!user) {
            return null
        }

        const { password: _, apiKey: __, ...rest } = user

        return rest
    }

    async changePassword(userId: string, currentPassword: string, newPassword: string) {
        return await this.usersService.changePassword(userId, currentPassword, newPassword)
    }
}
