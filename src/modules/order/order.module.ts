import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PassportModule } from '@nestjs/passport';
import { OrderService } from './order.service';
import { OrderController } from './order.controller';
import { OrderEntity } from '~/entities/order.entity';
import { UserEntity } from '~/entities/user.entity';
import { GameAccountEntity } from '~/entities/game-account.entity';

/**
 * ORDER MODULE
 * Module quản lý việc mua bán game account
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([OrderEntity, UserEntity, GameAccountEntity]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
  ],
  controllers: [OrderController],
  providers: [OrderService],
  exports: [OrderService],
})
export class OrderModule {}
