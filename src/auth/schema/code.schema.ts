import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type CodeDocument = HydratedDocument<Code>;

@Schema({ timestamps: true })
export class Code {
  @Prop({ type: String, required: true })
  code: string;

  @Prop({ type: Date, required: true })
  expiresAt: Date;

  @Prop({ type: String, required: true })
  email: string;
}

export const CodeSchema = SchemaFactory.createForClass(Code);
