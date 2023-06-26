import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Request,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from 'src/guard/auth.guard';
import { UserDto } from './dto/user.dto';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Get()
  @UseGuards(JwtAuthGuard)
  async getUser(@Request() req): Promise<any> {
    return this.userService.getUser({ _id: req.user.sub });
  }

  @Get('by-username/:username')
  @UseGuards(JwtAuthGuard)
  async getUserByUsername(
    @Request() req,
    @Param('username') username: string,
  ): Promise<any> {
    return this.userService.getUser({ username: username });
  }

  @Patch('')
  @UseGuards(JwtAuthGuard)
  async updateUser(@Request() req, @Body() dto: UserDto): Promise<any> {
    return this.userService.updateUser(req.user.sub, dto);
  }
}
