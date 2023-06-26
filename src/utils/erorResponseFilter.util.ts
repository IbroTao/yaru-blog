import { ArgumentsHost, Catch, HttpException } from '@nestjs/common';
import { AppErrorResponse } from './errorResponse.util';
import { BaseExceptionFilter } from '@nestjs/core';

@Catch(AppErrorResponse)
export class AppErrorResponseFilter extends BaseExceptionFilter {
  catch(exception: AppErrorResponse, host: ArgumentsHost): void {
    const message = exception.message;
    super.catch(new HttpException(message, exception.code), host);
  }
}
