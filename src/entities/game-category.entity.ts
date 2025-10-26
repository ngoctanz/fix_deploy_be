import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { GameAccountEntity } from './game-account.entity';

@Entity('game_category')
export class GameCategoryEntity {
  @PrimaryGeneratedColumn()
  gameCategoryId: number;

  @Column({ unique: true })
  gameCategoryName: string;

  @Column({ nullable: true })
  imageGameCategory: string;

  // Quan hệ One-to-Many: 1 category có nhiều game accounts
  @OneToMany(() => GameAccountEntity, (gameAccount) => gameAccount.gameCategory)
  gameAccounts: GameAccountEntity[];
}
