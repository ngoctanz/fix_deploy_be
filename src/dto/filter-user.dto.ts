import { IsOptional, IsEnum, IsInt, Min, IsString } from 'class-validator';
import { Type } from 'class-transformer';

/**
 * DTO để filter và phân trang Users (Admin)
 */
export class FilterUserDto {
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
  @IsEnum(['USER', 'ADMIN'], {
    message: 'Role phải là USER hoặc ADMIN',
  })
  role?: 'USER' | 'ADMIN';

  @IsOptional()
  @IsString()
  search?: string; // Tìm kiếm theo email
}
