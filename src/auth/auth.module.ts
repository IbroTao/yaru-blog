import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schema/auth.schema';
import { JwtSrategy } from './strategy';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { MailerModule } from '@nestjs-modules/mailer';
import { Code, CodeSchema, Token, TokenSchema } from './schema';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import * as moment from 'moment';

@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [
        ConfigModule,
        // envFilePath: '../../.env',
      ],
      useFactory: async (configService: ConfigService) => {
        return { secret: configService.get<string>('JWT_AUTH_SECRET') };
      },
      inject: [ConfigService],
    }),
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Code.name, schema: CodeSchema },
      { name: Token.name, schema: TokenSchema },
    ]),
    MailerModule.forRootAsync({
      useFactory: () => ({
        transport: `smtp://${process.env.SMTP_USER}:${process.env.SMTP_PASS}@smtp.gmail.com`,
        defaults: {
          from: '"test app" <noreply@test.com>',
        },
      }),
    }),
  ],
  controllers: [AuthController, UserController],
  providers: [
    AuthService,
    UserService,
    JwtSrategy,
    { provide: 'MomentWrapper', useValue: moment },
  ],
})
export class AuthModule {}
