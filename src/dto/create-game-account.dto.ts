import {
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateGameAccountDto {
  @IsNotEmpty({ message: 'Game category ID is required' })
  @IsNumber({}, { message: 'Game category ID must be a number' })
  @Type(() => Number)
  gameCategoryId: number;

  @IsNotEmpty({ message: 'Original price is required' })
  @IsNumber({}, { message: 'Original price must be a number' })
  @Min(0, { message: 'Original price must be greater than or equal to 0' })
  @Type(() => Number)
  originalPrice: number;

  @IsNotEmpty({ message: 'Current price is required' })
  @IsNumber({}, { message: 'Current price must be a number' })
  @Min(0, { message: 'Current price must be greater than or equal to 0' })
  @Type(() => Number)
  currentPrice: number;

  @IsOptional()
  @IsString({ message: 'Description must be a string' })
  description?: string;

  @IsOptional()
  @IsEnum(['available', 'sold', 'reserved'], {
    message: 'Status must be: available, sold, or reserved',
  })
  status?: 'available' | 'sold' | 'reserved';

  @IsOptional()
  @IsEnum(['VIP', 'Normal'], {
    message: 'Account type must be: VIP or Normal',
  })
  typeAccount?: 'VIP' | 'Normal';
}
