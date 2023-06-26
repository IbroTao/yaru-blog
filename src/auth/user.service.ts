import { HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schema';
import { Model } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import { AppErrorResponse } from 'src/utils';
import { UserDto } from './dto/user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private UserSchema: Model<UserDocument>,
    private config: ConfigService,
    private readonly mailService: MailerService,
  ) {}

  getUser = async (filter: any) => {
    try {
      const user = await this.UserSchema.findOne(filter);
      if (!user)
        throw new AppErrorResponse({
          error: 'user not found',
          status: HttpStatus.NOT_FOUND,
        });
      return user;
    } catch (error) {
      throw new AppErrorResponse({ error });
    }
  };
  updateUser = async (id: string, dto: UserDto) => {
    try {
      const user = await this.UserSchema.findByIdAndUpdate(
        id,
        { ...dto },
        { new: true },
      );
      if (dto.github) user.socials.github = dto.github;
      if (dto.twitter) user.socials.twitter = dto.twitter;
      return user;
    } catch (error) {
      throw new AppErrorResponse({ error });
    }
  };
}
