import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from 'src/common/auth/AuthGuard';
import { Request } from 'express';
import { userPayloadType } from 'src/common/types/auth.types';

@Controller('user')
@UseGuards(JwtAuthGuard)
export class UserController {
    constructor(
        private readonly userService: UserService
    ) { }
    /*
     Get user profile
     */
    @Get()
    async getProfile(@Req() req: Request) {
        const user = req['user'] as userPayloadType;
        const userProfile = await this.userService.getUserProfile(user.email);
        return {
            success: true,
            message: 'User profile retrieved successfully',
            data: userProfile,
        };
    }
}
