import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
} from 'typeorm';
import { UserEntity } from './user.entity';

@Entity('request_deposit')
export class RequestDepositEntity {
  @PrimaryGeneratedColumn()
  requestDepositId: number;

  @Column()
  userId: number;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({ nullable: true })
  imgUrl: string;

  @Column({
    type: 'enum',
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending',
  })
  status: 'pending' | 'approved' | 'rejected';

  @CreateDateColumn()
  createdAt: Date;

  // Quan hệ Many-to-One: Nhiều request thuộc về 1 user
  @ManyToOne(() => UserEntity, (user) => user.requestDeposits)
  @JoinColumn({ name: 'userId' })
  user: UserEntity;
}
