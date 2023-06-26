import { IError } from 'src/interfaces';

export class AppErrorResponse extends Error {
  public code: number;
  constructor(error: IError) {
    super(error.error);
    this.name = 'App Error Response';
    this.code = error.status || 500;
  }
}
