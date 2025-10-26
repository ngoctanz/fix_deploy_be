import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
} from 'typeorm';
import { UserEntity } from './user.entity';
import { GameAccountEntity } from './game-account.entity';

/**
 * Entity Order - Quản lý đơn hàng mua tài khoản game
 * Mỗi order liên kết với 1 user (người mua) và 1 game account (tài khoản được mua)
 */
@Entity('order')
export class OrderEntity {
  @PrimaryGeneratedColumn()
  orderId: number;

  @Column()
  gameAccountId: number;

  @Column()
  userId: number;

  // Timestamp khi order được tạo
  @CreateDateColumn()
  createdAt: Date;

  // Quan hệ Many-to-One: Nhiều order thuộc về 1 user
  @ManyToOne(() => UserEntity, (user) => user.orders)
  @JoinColumn({ name: 'userId' })
  user: UserEntity;

  // Quan hệ Many-to-One: Nhiều order có thể tham chiếu đến 1 game account
  @ManyToOne(() => GameAccountEntity, (gameAccount) => gameAccount.orders)
  @JoinColumn({ name: 'gameAccountId' })
  gameAccount: GameAccountEntity;
}
