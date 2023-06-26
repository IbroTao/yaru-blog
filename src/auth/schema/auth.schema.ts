import { Prop, Schema, SchemaFactory, raw } from '@nestjs/mongoose';
import { isEmail } from 'class-validator';
import { HydratedDocument } from 'mongoose';
import { hash } from 'argon2';
import toJSON from './plugins/toJson.plugin';

export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true })
export class User {
  @Prop({ type: String, required: true, minlength: 2 })
  name: string;

  @Prop({
    type: String,
    required: true,
    unique: true,
    index: true,
    minlength: 2,
  })
  username: string;

  @Prop({
    type: String,
    required: true,
    unique: true,
    index: true,
    validator: [
      { validator: isEmail, message: () => 'provide a valid email address' },
    ],
  })
  email: string;

  @Prop({
    type: String,
    required: true,
    minlength: 5,
    maxlength: 20,
    private: true,
  })
  password: string;

  @Prop(
    raw({
      twitter: { type: String },
      github: { type: String },
    }),
  )
  socials: Record<string, any>;

  @Prop({ type: String, required: false })
  pic: string;

  @Prop({ type: String, required: false, minlength: 20, maxlength: 250 })
  description: string;

  @Prop({ type: Boolean, default: false, private: true })
  isEmailVerified: boolean;

  @Prop({
    type: String,
    default: 'reader',
    enum: ['reader', 'author', 'admin'],
  })
  role: string;
}

const UserSchema = SchemaFactory.createForClass(User);
UserSchema.plugin(toJSON);

UserSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await hash(this.password);
  }
  next();
});

export { UserSchema };
