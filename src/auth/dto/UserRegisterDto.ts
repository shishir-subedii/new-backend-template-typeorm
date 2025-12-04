import { IsEmail, IsEnum, IsString, MinLength } from 'class-validator';
export class UserRegisterDto {

    @IsString()
    name: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;

    @IsString()
    confirmPassword: string;
}

//Remaining data we will update later