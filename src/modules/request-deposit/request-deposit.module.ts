import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PassportModule } from '@nestjs/passport';
import { RequestDepositService } from './request-deposit.service';
import { RequestDepositController } from './request-deposit.controller';
import { RequestDepositEntity } from '~/entities/request-deposit.entity';
import { UserEntity } from '~/entities/user.entity';
import { CloudinaryModule } from '../cloudinary/cloudinary.module';

/**
 * REQUEST DEPOSIT MODULE
 * Import các dependencies:
 * - TypeORM: RequestDepositEntity, UserEntity
 * - PassportModule: JWT authentication
 * - CloudinaryModule: Upload ảnh bill
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([RequestDepositEntity, UserEntity]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    CloudinaryModule,
  ],
  controllers: [RequestDepositController],
  providers: [RequestDepositService],
  exports: [RequestDepositService],
})
export class RequestDepositModule {}
