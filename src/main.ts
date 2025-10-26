import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { envConfig } from './config/env.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const config = envConfig(configService);

  // gobal middlware
  // app.use(new LoggingMiddleware().use);
  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Bỏ field không khai báo trong DTO
      forbidNonWhitelisted: false, // Trả lỗi nếu có field thừa là true
      transform: true, // Tự chuyển đổi kiểu dữ liệu
      transformOptions: { enableImplicitConversion: true },
      disableErrorMessages: false,
    }),
  );
  // Mở CORS
  const allowedOrigins = [
    'http://localhost:3000',
    'https://deployfixas.vercel.app',
    configService.get<string>('DOMAIN_FRONTEND'),
  ].filter(Boolean);

  app.enableCors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
    exposedHeaders: ['Set-Cookie'],
  });

  await app.listen(config.app.port);

  console.log(`🚀 Application running on: http://localhost:${config.app.port}`);
  console.log(`📝 Environment: ${config.app.nodeEnv}`);
}
bootstrap();
