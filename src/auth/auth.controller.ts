import { Body, Controller, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  LoginDto,
  LogoutDto,
  RefreshDto,
  RegisterDto,
  VerifyEmailDto,
} from './dto/auth.dto';
import { AppErrorResponse } from 'src/utils';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: RegisterDto): Promise<string | Error> {
    return this.authService.register(dto);
  }

  @Post('login')
  async login(@Body() dto: LoginDto): Promise<any> {
    const { accessToken, refreshToken, user } = await this.authService.login(
      dto,
    );
    const returnObj = {
      tokens: {
        accessToken,
        refreshToken,
      },
      user,
    };
    return returnObj;
  }

  @Post('logout')
  async logout(@Body() dto: LogoutDto): Promise<any> {
    try {
      await this.authService.logout(dto);
    } catch (error) {
      throw new AppErrorResponse({
        error,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
      });
    }
  }

  @Post('verify-email')
  async verifyEmail(@Body() dto: VerifyEmailDto): Promise<any> {
    return this.authService.verifyEmail(dto);
  }

  @Post('refresh-tokens')
  async refreshToken(@Body() dto: RefreshDto): Promise<any> {
    const { accessToken, refreshToken } = await this.authService.refreshToken(
      dto,
    );
    return {
      tokens: {
        access: accessToken,
        refresh: refreshToken,
      },
    };
  }
}
