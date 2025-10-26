import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PassportModule } from '@nestjs/passport';
import { GameAccountService } from './game-account.service';
import { GameAccountController } from './game-account.controller';
import { GameAccountEntity } from '~/entities/game-account.entity';
import { ImageEntity } from '~/entities/image.entity';
import { GameCategoryEntity } from '~/entities/game-category.entity';
import { CloudinaryModule } from '../cloudinary/cloudinary.module';
import { CloudinaryService } from '../cloudinary/cloudinary.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      GameAccountEntity,
      ImageEntity,
      GameCategoryEntity,
    ]),
    PassportModule, // Để dùng Guards
    CloudinaryModule,
  ],
  controllers: [GameAccountController],
  providers: [GameAccountService, CloudinaryService],
  exports: [GameAccountService],
})
export class GameAccountModule {}
