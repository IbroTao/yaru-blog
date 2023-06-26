import { IsOptional, IsString } from 'class-validator';

export class UserDto {
  @IsString()
  @IsOptional()
  twitter: string;

  @IsString()
  @IsOptional()
  github: string;

  @IsString()
  @IsOptional()
  type: string;

  @IsString()
  @IsOptional()
  description: string;

  @IsString()
  @IsOptional()
  name: string;
}
