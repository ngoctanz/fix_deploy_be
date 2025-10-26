export class ResponseData<T> {
  status: number;
  message: string;
  data: T | null;

  constructor(status: number, message: string, data: T) {
    this.status = status;
    this.message = message;
    this.data = data;
  }
}
