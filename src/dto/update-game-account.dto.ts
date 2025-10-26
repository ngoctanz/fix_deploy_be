import {
  IsEnum,
  IsNumber,
  IsOptional,
  IsString,
  Min,
  IsArray,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';

export class UpdateGameAccountDto {
  @IsOptional()
  @IsNumber({}, { message: 'Game category ID must be a number' })
  @Type(() => Number)
  gameCategoryId?: number;

  @IsOptional()
  @IsNumber({}, { message: 'Original price must be a number' })
  @Min(0, { message: 'Original price must be >= 0' })
  @Type(() => Number)
  originalPrice?: number;

  @IsOptional()
  @IsNumber({}, { message: 'Current price must be a number' })
  @Min(0, { message: 'Current price must be >= 0' })
  @Type(() => Number)
  currentPrice?: number;

  @IsOptional()
  @IsString({ message: 'Description must be a string' })
  description?: string;

  @IsOptional()
  @IsEnum(['available', 'sold', 'reserved'], {
    message: 'Status must be one of: available, sold, reserved',
  })
  status?: 'available' | 'sold' | 'reserved';

  @IsOptional()
  @IsEnum(['VIP', 'Normal'], {
    message: 'Account type must be one of: VIP, Normal',
  })
  typeAccount?: 'VIP' | 'Normal';

  @IsOptional()
  @Transform(({ value }) => {
    if (typeof value === 'string') {
      try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) return parsed.map((v) => Number(v));
      } catch {
        return [];
      }
    }
    return value;
  })
  @IsArray({ message: 'deleteImageIds must be an array' })
  @IsNumber({}, { each: true, message: 'Each imageId must be a number' })
  deleteImageIds?: number[];
}
