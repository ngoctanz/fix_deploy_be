import { IsOptional, IsEnum, IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';

/**
 * DTO để filter và phân trang Request Deposits
 */
export class FilterRequestDepositDto {
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
  @IsEnum(['pending', 'approved', 'rejected'], {
    message: 'Status phải là pending, approved, hoặc rejected',
  })
  status?: 'pending' | 'approved' | 'rejected';

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  userId?: number; // Filter theo userId (cho admin)
}
