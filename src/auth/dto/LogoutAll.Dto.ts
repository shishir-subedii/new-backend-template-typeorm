import { IsString } from "class-validator";

export class LogOutAllDto {
    @IsString()
    password: string
}