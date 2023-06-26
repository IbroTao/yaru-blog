import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import moment from 'moment';
import { Code, User, UserDocument, CodeSchema, CodeDocument } from './schema';
import { RegisterDto } from './dto/auth.dto';
import { AppErrorResponse, uniqueSixDigits } from 'src/utils';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserSchema: Model<UserDocument>,
    @InjectModel(Code.name) private CodeSchema: Model<CodeDocument>,
    private jwt: JwtService,
    private config: ConfigService,
    private readonly mailService: MailerService,
  ) {}

  register = async (dto: RegisterDto): Promise<string> => {
    const isEmailTaken = await this.UserSchema.findOne({ email: dto.email });
    if (isEmailTaken)
      throw new AppErrorResponse({
        error: 'email not available',
        status: 400,
      });
    const isUsernameTaken = await this.UserSchema.findOne({
      username: dto.username,
    });
    if (isUsernameTaken)
      throw new AppErrorResponse({
        error: 'username not available',
        status: 400,
      });
    await this.UserSchema.create({ ...dto });
    const sixDigitsCode = uniqueSixDigits();
    await this.CodeSchema.create({
      email: dto.email,
      code: sixDigitsCode,
      expiresAt: new Date().getHours() + 1,
    });
    const mailContent = `Dear user,
  To verify your email, here is your six digits code: ${sixDigitsCode}
  Note: the code expires in an hour,
  If you did not create an account, then ignore this email.`;
    await this.sendMail(dto.email, 'Registration Successful', mailContent);
    return 'success';
  };

  sendMail = async (to: string, subject: string, text: string) => {
    this.mailService
      .sendMail({
        to,
        subject,
        text,
      })
      .then((result) => result)
      .catch((err) => {
        console.log(err);
        throw new AppErrorResponse({
          error: err,
          status: 500,
        });
      });
  };

  signToken = async (userId: string, role: string, expires: moment.Moment) => {
    const payload = {
      sub: userId,
      iat: moment().unix(),
      exp: expires.unix(),
      role,
    };

    const token: string = await this.jwt.signAsync(payload, {
      secret: this.config.get('JWT_AUTH_SECRET'),
    });
    return token;
  };

  generateAuthTokens = async (user: UserDocument) => {
    const accessToken = await this.signToken(
      user._id.toHexString(),
      user.role,
      this.config.get('JWT_ACCESS_TOKEN_EXPIRATION'),
    );
    const refreshToken = await this.signToken(
      user._id.toHexString(),
      user.role,
      this.config.get('JWT_REFRESH_TOKEN_EXPIRATION'),
    );

    return {
      accessToken,
      refreshToken,
    };
  };
}
