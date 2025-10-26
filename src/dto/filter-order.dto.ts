import { IsOptional, IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';

/**
 * DTO để filter và phân trang Orders
 */
export class FilterOrderDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  limit?: number = 10;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  userId?: number; // Filter theo userId (admin only)

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  gameAccountId?: number; // Filter theo gameAccountId
}
