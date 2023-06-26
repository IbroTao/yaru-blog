import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto, verifyEmailDto } from './dto/auth.dto';

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

  @Post('verify-email')
  async verifyEmail(@Body() dto: verifyEmailDto): Promise<any> {
    return this.authService.verifyEmail(dto);
  }
}
