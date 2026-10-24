import { GUARDS_METADATA } from "@nestjs/common/constants"
import { Test, TestingModule } from "@nestjs/testing"
import { Reflector } from "@nestjs/core"

import { ROLES_KEY } from "../auth/decorators/roles.decorator"
import { UserRole } from "../generated/prisma/enums"

import { RESOURCE_SERVICE_KEY } from "../common/guards/ownership.guard"
import { UsersController } from "./users.controller"
import { UsersService } from "./users.service"

describe("UsersController", () => {
    let controller: UsersController
    let service: UsersService

    const mockUsersService = {
        create: jest.fn(),
        findAll: jest.fn(),
        findOne: jest.fn(),
        update: jest.fn(),
        remove: jest.fn(),
    }

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [UsersController],
            providers: [
                { provide: UsersService, useValue: mockUsersService },
                { provide: RESOURCE_SERVICE_KEY, useValue: mockUsersService },
                Reflector,
            ],
        }).compile()

        controller = module.get<UsersController>(UsersController)
        service = module.get<UsersService>(UsersService)
    })

    it("should be defined", () => {
        expect(controller).toBeDefined()
    })

    describe("create", () => {
        it("should call service.create", async () => {
            const dto = { email: "test@test.com" } as any
            await controller.create(dto)
            expect(service.create).toHaveBeenCalledWith(dto)
        })
    })

    describe("findAll", () => {
        it("should call service.findAll", async () => {
            await controller.findAll(1, 10)
            expect(service.findAll).toHaveBeenCalledWith({ page: 1, perPage: 10 })
        })
    })

    describe("findOne", () => {
        it("should call service.findOne", async () => {
            await controller.findOne("1")
            expect(service.findOne).toHaveBeenCalledWith("1")
        })
    })

    describe("update", () => {
        it("should call service.update", async () => {
            const dto = { name: "Updated" } as any
            await controller.update("1", dto)
            expect(service.update).toHaveBeenCalledWith("1", dto)
        })
    })

    describe("remove", () => {
        it("should call service.remove", async () => {
            await controller.remove("1")
            expect(service.remove).toHaveBeenCalledWith("1")
        })
    })

    describe("authorization metadata", () => {
        it("only admins can create users directly", () => {
            expect(Reflect.getMetadata(ROLES_KEY, UsersController.prototype.create)).toEqual([UserRole.ADMIN])
        })

        it("findOne is protected by the ownership guard", () => {
            const guards = Reflect.getMetadata(GUARDS_METADATA, UsersController.prototype.findOne) ?? []
            expect(guards).toHaveLength(1)
        })
    })
})
