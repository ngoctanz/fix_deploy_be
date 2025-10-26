import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { GameCategoryEntity } from './game-category.entity';
import { ImageEntity } from './image.entity';
import { OrderEntity } from './order.entity';

@Entity('game_account')
export class GameAccountEntity {
  @PrimaryGeneratedColumn()
  gameAccountId: number;

  @Column({
    type: 'enum',
    enum: ['available', 'sold', 'reserved'],
    default: 'available',
  })
  status: 'available' | 'sold' | 'reserved';

  @Column()
  gameCategoryId: number;

  // Giá gốc ban đầu
  @Column({ type: 'decimal', precision: 10, scale: 2 })
  originalPrice: number;

  // Giá hiện tại (có thể giảm giá)
  @Column({ type: 'decimal', precision: 10, scale: 2 })
  currentPrice: number;

  // Mô tả chi tiết về tài khoản (rank, skin, tướng, etc.)
  @Column({ type: 'text', nullable: true })
  description: string;

  // Ảnh chính/đại diện của tài khoản
  @Column({ nullable: true })
  mainImageUrl: string;

  // Loại tài khoản: VIP hoặc Normal
  @Column({
    type: 'enum',
    enum: ['VIP', 'Normal'],
    default: 'Normal',
  })
  typeAccount: 'VIP' | 'Normal';

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Quan hệ Many-to-One: Nhiều game account thuộc 1 category
  @ManyToOne(() => GameCategoryEntity, (category) => category.gameAccounts)
  @JoinColumn({ name: 'gameCategoryId' })
  gameCategory: GameCategoryEntity;

  // Quan hệ One-to-Many: 1 game account có nhiều images
  @OneToMany(() => ImageEntity, (image) => image.gameAccount)
  images: ImageEntity[];

  // Quan hệ One-to-Many: 1 game account có thể có nhiều orders
  @OneToMany(() => OrderEntity, (order) => order.gameAccount)
  orders: OrderEntity[];
}
