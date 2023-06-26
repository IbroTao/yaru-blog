import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { Connection } from 'mongoose';
import { Code, CodeSchema, User, UserSchema } from './auth/schema';
import { AuthModule } from './auth/auth.module';
import { AppErrorResponseFilter } from './utils/erorResponseFilter.util';
import { APP_FILTER } from '@nestjs/core';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRoot(process.env.MONGO_URI, {
      connectionFactory: (connection: Connection) => {
        return connection;
      },
    }),
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Code.name, schema: CodeSchema },
    ]),
    AuthModule,
  ],
  providers: [{ provide: APP_FILTER, useClass: AppErrorResponseFilter }],
})
export class AppModule {}
