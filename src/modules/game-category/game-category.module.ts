import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PassportModule } from '@nestjs/passport';
import { GameCategoryService } from './game-category.service';
import { GameCategoryController } from './game-category.controller';
import { GameCategoryEntity } from '~/entities/game-category.entity';
import { CloudinaryModule } from '../cloudinary/cloudinary.module';

/**
 * GAME CATEGORY MODULE
 * Import TypeOrmModule để sử dụng repository
 * Import CloudinaryModule để upload ảnh
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([GameCategoryEntity]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    CloudinaryModule,
  ],
  controllers: [GameCategoryController],
  providers: [GameCategoryService],
  exports: [GameCategoryService], // Export để module khác có thể dùng
})
export class GameCategoryModule {}
