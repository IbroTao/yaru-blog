import { IsEmail, IsJWT, IsNotEmpty, IsString } from 'class-validator';

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class LoginDto {
  @IsString()
  @IsNotEmpty()
  emailOrUsername: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class VerifyEmailDto {
  @IsString()
  @IsNotEmpty()
  code: string;
}

export class LogoutDto {
  @IsString()
  @IsNotEmpty()
  @IsJWT()
  token: string;
}

export class RefreshDto extends LogoutDto {}
