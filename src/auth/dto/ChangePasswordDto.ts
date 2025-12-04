import { IsString } from "class-validator";

export class changePasswordDto {
    @IsString()
    oldPassword: string;

    @IsString()
    newPassword: string;

    @IsString()
    confirmNewPassword: string;
}