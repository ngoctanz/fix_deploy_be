import { Injectable, NestMiddleware } from '@nestjs/common';

@Injectable()
export class LoggingMiddleware implements NestMiddleware {
  use(req: any, res: any, next: () => void) {
    console.log(req.url);
    req.user = { id: 1, name: 'John Doe' }; // Thêm thông tin user giả lập vào request
    next();
  }
}
