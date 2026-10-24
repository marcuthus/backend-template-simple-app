import { ConflictException, Injectable, NotFoundException } from "@nestjs/common"
import { createPaginator, PaginateOptions } from "prisma-pagination"

import { messagesHelper } from "../helpers/messages.helper"
import { generateApiKey } from "../utils/generate-api-key"
import { Prisma, User } from "../generated/prisma/client"
import { PrismaService } from "../prisma/prisma.service"
import { CryptoService } from "../crypto/crypto.service"
import { UpdateUserDto } from "./dto/update-user.dto"
import { CreateUserDto } from "./dto/create-user.dto"

const sensitiveFields = {
    password: true,
    apiKey: true,
} as const

@Injectable()
export class UsersService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly cryptoService: CryptoService,
    ) {}

    async create(createUserDto: CreateUserDto) {
        const { password, ...rest } = createUserDto

        const existingUser = await this.prisma.user.findFirst({
            where: {
                OR: [{ email: createUserDto.email }, { username: createUserDto.username }],
            },
            select: {
                email: true,
            },
        })

        if (existingUser) {
            const property = createUserDto.email === existingUser.email ? "email" : "username"

            throw new ConflictException(
                messagesHelper.OBJECT_ALREADY_EXISTS({
                    name: "User",
                    property: property,
                    value: createUserDto[property],
                }),
            )
        }

        const generatedApiKey = generateApiKey()
        const encryptedApiKey = this.cryptoService.encrypt(generatedApiKey)
        const hashedPassword = await this.cryptoService.hashPassword(password)

        const user = await this.prisma.user.create({
            data: {
                ...rest,
                apiKey: encryptedApiKey,
                password: hashedPassword,
            },
            omit: sensitiveFields,
        })

        // A API key em texto puro só é exibida uma vez, na criação (no banco ela fica criptografada).
        return {
            ...user,
            apiKey: generatedApiKey,
        }
    }

    async findAll({ page, perPage }: PaginateOptions) {
        const paginate = createPaginator({
            page: page,
            perPage: perPage,
        })

        return await paginate<User, Prisma.UserFindManyArgs>(this.prisma.user, {
            omit: sensitiveFields,
        })
    }

    async findOne(id: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: id,
            },
            omit: sensitiveFields,
        })

        if (!user) {
            throw new NotFoundException(
                messagesHelper.OBJECT_NOT_FOUND({
                    name: "User",
                    value: id,
                }),
            )
        }

        return user
    }

    async findOneByEmail(email: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: email,
            },
        })

        if (!user) {
            throw new NotFoundException(
                messagesHelper.OBJECT_NOT_FOUND({
                    name: "User",
                    property: "email",
                    value: email,
                }),
            )
        }

        return user
    }

    async safeFindOneByEmail(email: string) {
        try {
            return await this.findOneByEmail(email)
        } catch (error) {
            if (error instanceof NotFoundException) {
                return null
            }

            throw error
        }
    }

    async safeFindOneByApiKey(apiKey: string) {
        const encryptedApiKey = this.cryptoService.encrypt(apiKey)

        return await this.prisma.user.findUnique({
            where: {
                apiKey: encryptedApiKey,
            },
        })
    }

    async findOneByApiKey(apiKey: string) {
        const user = await this.safeFindOneByApiKey(apiKey)

        if (!user) {
            // Não inclui a chave na mensagem para não ecoar segredos em respostas/logs.
            throw new NotFoundException(messagesHelper.INVALID_API_KEY)
        }

        return user
    }

    async update(id: string, updateUserDto: UpdateUserDto) {
        const existingUser = await this.prisma.user.findUnique({
            where: {
                id: id,
            },
            select: {
                id: true,
            },
        })

        if (!existingUser) {
            throw new NotFoundException(
                messagesHelper.OBJECT_NOT_FOUND({
                    name: "User",
                    property: "id",
                    value: id,
                }),
            )
        }

        return await this.prisma.user.update({
            where: {
                id: id,
            },
            data: {
                ...updateUserDto,
            },
            omit: sensitiveFields,
        })
    }

    async remove(id: string) {
        const existingUser = await this.prisma.user.findUnique({
            where: {
                id: id,
            },
            select: {
                id: true,
            },
        })

        if (!existingUser) {
            throw new NotFoundException(
                messagesHelper.OBJECT_NOT_FOUND({
                    name: "User",
                    property: "id",
                    value: id,
                }),
            )
        }

        await this.prisma.user.delete({
            where: {
                id: id,
            },
            select: {
                id: true,
            },
        })
    }

    async changePassword(userId: string, currentPassword: string, newPassword: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId,
            },
        })

        if (!user) {
            throw new NotFoundException(
                messagesHelper.OBJECT_NOT_FOUND({
                    name: "User",
                    property: "id",
                    value: userId,
                }),
            )
        }

        const isCurrentPasswordValid = await this.cryptoService.comparePasswords(currentPassword, user.password)

        if (!isCurrentPasswordValid) {
            throw new ConflictException(messagesHelper.INVALID_CREDENTIALS)
        }

        const hashedNewPassword = await this.cryptoService.hashPassword(newPassword)

        await this.prisma.user.update({
            where: {
                id: userId,
            },
            data: {
                password: hashedNewPassword,
            },
        })
    }
}
