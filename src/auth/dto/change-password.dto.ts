import { IsNotEmpty, IsString, Matches } from "class-validator"
import { ApiProperty } from "@nestjs/swagger"

import { regexHelper } from "../../helpers/regex.helper"

// Sem decorators, o ValidationPipe (whitelist + forbidNonWhitelisted) rejeitava todos os campos.
export class ChangePasswordDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    currentPassword: string

    @ApiProperty()
    @Matches(regexHelper.password)
    newPassword: string
}
