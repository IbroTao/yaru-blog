import { Controller, Get, Param, Request, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from 'src/guard/auth.guard';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Get(':username')
  @UseGuards(JwtAuthGuard)
  async getUserByUsername(@Request() req): Promise<any> {
    return `hello there ${req.user}`;
  }
}
