import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schema';
import { Model } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private UserSchema: Model<UserDocument>,
    private config: ConfigService,
    private readonly mailService: MailerService,
  ) {}
}
