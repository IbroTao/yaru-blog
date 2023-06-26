/* eslint-disable @typescript-eslint/ban-ts-comment */
import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  Code,
  User,
  UserDocument,
  CodeDocument,
  TokenDocument,
  Token,
} from './schema';
import {
  LoginDto,
  LogoutDto,
  RefreshDto,
  RegisterDto,
  VerifyEmailDto,
} from './dto/auth.dto';
import { AppErrorResponse, uniqueSixDigits } from 'src/utils';
import { MailerService } from '@nestjs-modules/mailer';
import { verify } from 'argon2';
import moment from 'moment';
import { IPayload } from 'src/interfaces';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserSchema: Model<UserDocument>,
    @InjectModel(Code.name) private CodeSchema: Model<CodeDocument>,
    @InjectModel(Token.name) private TokenSchema: Model<TokenDocument>,
    @Inject('MomentWrapper') private momentWrapper: moment.Moment,
    private jwt: JwtService,
    private config: ConfigService,
    private readonly mailService: MailerService,
  ) {}

  register = async (dto: RegisterDto): Promise<string> => {
    try {
      const isEmailTaken = await this.UserSchema.findOne({ email: dto.email });
      if (isEmailTaken)
        throw new AppErrorResponse({
          error: 'email not available',
          status: HttpStatus.BAD_REQUEST,
        });
      const isUsernameTaken = await this.UserSchema.findOne({
        username: dto.username,
      });
      if (isUsernameTaken)
        throw new AppErrorResponse({
          error: 'username not available',
          status: HttpStatus.BAD_REQUEST,
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
    } catch (error) {
      throw new AppErrorResponse({
        error,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
      });
    }
  };

  verifyEmail = async (dto: VerifyEmailDto) => {
    try {
      const value = await this.CodeSchema.findOne({
        $and: [
          { code: dto.code },
          { expiresAt: { $gte: new Date().getHours() } },
        ],
      });
      if (!value)
        throw new AppErrorResponse({
          error: 'the code is invalid or it has expired, request for another',
          status: HttpStatus.BAD_REQUEST,
        });
      const user = await this.UserSchema.findOne({ email: value.email });
      if (!user)
        throw new AppErrorResponse({
          error: 'the code is invalid or it has expired, request for another',
          status: HttpStatus.BAD_REQUEST,
        });
      await this.UserSchema.updateOne(
        { _id: user._id },
        { $set: { isEmailVerified: true } },
      );
      await this.CodeSchema.deleteOne({
        $and: [{ email: value.email }, { code: dto.code }],
      });
      return 'success';
    } catch (error) {
      throw new AppErrorResponse({
        error,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
      });
    }
  };

  login = async (dto: LoginDto) => {
    try {
      const user = await this.UserSchema.findOne({
        $or: [
          { email: dto.emailOrUsername },
          { username: dto.emailOrUsername },
        ],
      });
      if (!user)
        throw new AppErrorResponse({
          error: 'incorrect credentials',
          status: HttpStatus.BAD_REQUEST,
        });
      if (!user.isEmailVerified)
        throw new AppErrorResponse({
          error: 'verify email in order to login',
          status: HttpStatus.FORBIDDEN,
        });
      if (!(await verify(user.password, dto.password)))
        throw new AppErrorResponse({
          error: 'incorrect credentials',
          status: HttpStatus.BAD_REQUEST,
        });
      const { accessToken, refreshToken } = await this.generateAuthTokens(user);
      //@ts-ignore
      const expires = this.momentWrapper().add(
        this.config.get('JWT_REFRESH_TOKEN_EXPIRATION'),
        'days',
      );
      await this.saveToken(refreshToken, user.id, expires, 'refresh');
      return { accessToken, refreshToken, user };
    } catch (error) {
      throw new AppErrorResponse({
        error,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
      });
    }
  };

  logout = async (dto: LogoutDto): Promise<any> => {
    const refreshTokenDoc = await this.TokenSchema.findOne({
      token: dto.token,
      type: 'refresh',
      blacklisted: false,
    });
    if (!refreshTokenDoc)
      throw new AppErrorResponse({
        status: HttpStatus.NOT_FOUND,
        error: 'token not found',
      });
    return this.TokenSchema.findByIdAndDelete(refreshTokenDoc._id);
  };

  refreshToken = async (dto: RefreshDto) => {
    try {
      const { token, tokenDoc } = await this.verifyToken(dto.token);
      const user = await this.UserSchema.findById(tokenDoc.sub);
      if (!user) throw new AppErrorResponse({ error: 'user not found' });
      await this.TokenSchema.deleteOne({ token });
      return this.generateAuthTokens(user);
    } catch (error) {
      throw new AppErrorResponse({
        error,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
      });
    }
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
        throw new AppErrorResponse({
          error: err,
          status: HttpStatus.INTERNAL_SERVER_ERROR,
        });
      });
  };

  signToken = async (userId: string, role: string, expires: moment.Moment) => {
    const payload: IPayload = {
      sub: userId,
      //@ts-ignore
      iat: this.momentWrapper().unix(),
      exp: expires.unix(),
      role,
    };

    const token: string = await this.jwt.signAsync(payload, {
      secret: this.config.get('JWT_AUTH_SECRET'),
    });
    return token;
  };

  generateAuthTokens = async (user: UserDocument) => {
    try {
      const accessDuraton = this.config.get('JWT_ACCESS_TOKEN_EXPIRATION');
      const refreshDuration = this.config.get('JWT_REFRESH_TOKEN_EXPIRATION');
      const accessToken = await this.signToken(
        user._id.toHexString(),
        user.role,
        //@ts-ignore
        this.momentWrapper().add(accessDuraton, 'minutes'),
      );
      const refreshToken = await this.signToken(
        user._id.toHexString(),
        user.role,
        //@ts-ignore
        this.momentWrapper().add(refreshDuration, 'days'),
      );

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw new AppErrorResponse({ error });
    }
  };

  saveToken = async (
    token: string,
    userId: string,
    expires: moment.Moment,
    type: string,
    blacklisted = false,
  ) => {
    return this.TokenSchema.create({
      token,
      userId,
      type,
      expires,
      blacklisted,
    });
  };

  verifyToken = async (token: string) => {
    try {
      const secret = this.config.get('JWT_AUTH_SECRET');
      const payload = await this.jwt.verifyAsync(token, secret);
      const tokenDoc: IPayload | null = await this.TokenSchema.findOne({
        token,
        type: 'refresh',
        userId: payload.sub,
        blacklisted: false,
      });
      if (!tokenDoc)
        throw new AppErrorResponse({
          error: 'token not found',
          status: HttpStatus.NOT_FOUND,
        });
      return { tokenDoc, token };
    } catch (error) {
      throw new AppErrorResponse({ error });
    }
  };
}
