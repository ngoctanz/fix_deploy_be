import { CloudinaryModule } from './modules/cloudinary/cloudinary.module';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AuthModule } from '~/modules/auth/auth.module';
import { UserModule } from '~/modules/user/user.module';
import { AppService } from '~/app.service';
import { typeOrmConfig } from './config/database.config';
import { GameCategoryModule } from './modules/game-category/game-category.module';
import { RequestDepositModule } from './modules/request-deposit/request-deposit.module';
import { OrderModule } from './modules/order/order.module';
import { GameAccountModule } from './modules/game-account/game-account.module';

@Module({
  imports: [
    CloudinaryModule,
    CloudinaryModule,
    // 1️⃣ Nạp module Config để đọc các biến môi trường từ file .env
    ConfigModule.forRoot({
      isGlobal: true, // Cho phép truy cập ConfigService ở mọi nơi
      envFilePath: '.env',
    }),
    // 2️⃣ Cấu hình kết nối database với TypeORM - Dùng ConfigService
    TypeOrmModule.forRootAsync({
      useFactory: (configService: ConfigService) =>
        typeOrmConfig(configService),
      inject: [ConfigService],
    }),
    UserModule,
    AuthModule,
    GameAccountModule,
    GameCategoryModule,
    RequestDepositModule,
    OrderModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
