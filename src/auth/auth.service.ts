import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import moment from 'moment';
import { Code, User, UserDocument, CodeSchema, CodeDocument } from './schema';
import { LoginDto, RegisterDto, verifyEmailDto } from './dto/auth.dto';
import { AppErrorResponse, uniqueSixDigits } from 'src/utils';
import { MailerService } from '@nestjs-modules/mailer';
import { verify } from 'argon2';

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

  verifyEmail = async (dto: verifyEmailDto) => {
    const value = await this.CodeSchema.findOne({
      $and: [
        { code: dto.code },
        { expiresAt: { $gte: new Date().getHours() } },
      ],
    });
    if (!value)
      throw new AppErrorResponse({
        error: 'the code is invalid or it has expired, request for another',
        status: 400,
      });
    const user = await this.UserSchema.findOne({ email: value.email });
    if (!user)
      throw new AppErrorResponse({
        error: 'the code is invalid or it has expired, request for another',
        status: 400,
      });
    await this.UserSchema.updateOne(
      { _id: user._id },
      { $set: { isEmailVerified: true } },
    );
    await this.CodeSchema.deleteOne({
      $and: [{ email: value.email }, { code: dto.code }],
    });
    return 'success';
  };

  login = async (dto: LoginDto) => {
    const user = await this.UserSchema.findOne({
      $or: [{ email: dto.emailOrUsername }, { username: dto.emailOrUsername }],
    });
    if (!user)
      throw new AppErrorResponse({
        error: 'incorrect credentials',
        status: 404,
      });

    if (!(await verify(user.password, dto.password)))
      throw new AppErrorResponse({
        error: 'incorrect credentials',
        status: 400,
      });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, email, ...rest } = user;
    const { accessToken, refreshToken } = await this.generateAuthTokens(user);
    return { accessToken, refreshToken, user: rest };
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
