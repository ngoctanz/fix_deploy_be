import {
  IsEnum,
  IsNumber,
  IsOptional,
  IsString,
  Min,
  IsArray,
} from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateGameAccountDto {
  @IsOptional()
  @IsNumber({}, { message: 'Game category ID must be a number' })
  @Type(() => Number)
  gameCategoryId?: number;

  @IsOptional()
  @IsNumber({}, { message: 'Original price must be a number' })
  @Min(0, { message: 'Original price must be greater than or equal to 0' })
  @Type(() => Number)
  originalPrice?: number;

  @IsOptional()
  @IsNumber({}, { message: 'Current price must be a number' })
  @Min(0, { message: 'Current price must be greater than or equal to 0' })
  @Type(() => Number)
  currentPrice?: number;

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

  /**
   * List of image IDs to delete
   * Frontend sends array of imageIds to delete during update
   */
  @IsOptional()
  @IsArray({ message: 'deleteImageIds must be an array' })
  @IsNumber({}, { each: true, message: 'Each imageId must be a number' })
  @Type(() => Number)
  deleteImageIds?: number[];
}
