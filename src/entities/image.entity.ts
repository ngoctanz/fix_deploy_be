import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { GameAccountEntity } from './game-account.entity';

@Entity('image')
export class ImageEntity {
  @PrimaryGeneratedColumn()
  imageId: number;

  // URL của hình ảnh
  @Column()
  imageUrl: string;

  // Tên/mô tả hình ảnh
  @Column()
  imageName: string;

  @Column()
  gameAccountId: number;

  // Quan hệ Many-to-One: Nhiều image thuộc về 1 game account
  @ManyToOne(() => GameAccountEntity, (gameAccount) => gameAccount.images)
  @JoinColumn({ name: 'gameAccountId' })
  gameAccount: GameAccountEntity;
}
