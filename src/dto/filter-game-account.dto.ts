import { IsEnum, IsNumber, IsOptional, IsString, Min } from 'class-validator';
import { Type } from 'class-transformer';

/**
 * DTO cho filter, sort và pagination Game Account
 * Hỗ trợ tìm kiếm, lọc theo nhiều tiêu chí và sắp xếp linh hoạt
 */
export class FilterGameAccountDto {
  // ========== PAGINATION ==========
  @IsOptional()
  @IsNumber({}, { message: 'Page phải là số' })
  @Min(1, { message: 'Page phải lớn hơn hoặc bằng 1' })
  @Type(() => Number)
  page?: number = 1;

  @IsOptional()
  @IsNumber({}, { message: 'Limit phải là số' })
  @Min(1, { message: 'Limit phải lớn hơn hoặc bằng 1' })
  @Type(() => Number)
  limit?: number = 10;

  // ========== FILTERING ==========

  /**
   * Lọc theo Game Category ID
   * VD: gameCategoryId=1
   */
  @IsOptional()
  @IsNumber({}, { message: 'Game category ID phải là số' })
  @Type(() => Number)
  gameCategoryId?: number;

  /**
   * Lọc theo trạng thái: available, sold, reserved
   * VD: status=available
   */
  @IsOptional()
  @IsEnum(['available', 'sold', 'reserved'], {
    message: 'Trạng thái phải là: available, sold, hoặc reserved',
  })
  status?: 'available' | 'sold' | 'reserved';

  /**
   * Lọc theo loại tài khoản: VIP hoặc Normal
   * VD: typeAccount=VIP
   */
  @IsOptional()
  @IsEnum(['VIP', 'Normal'], {
    message: 'Loại tài khoản phải là: VIP, Normal',
  })
  typeAccount?: 'VIP' | 'Normal';

  /**
   * Tìm kiếm theo từ khóa trong description
   * VD: search=rank cao
   */
  @IsOptional()
  @IsString({ message: 'Search phải là chuỗi' })
  search?: string;

  /**
   * Giá tối thiểu
   * VD: minPrice=100000
   */
  @IsOptional()
  @IsNumber({}, { message: 'Min price phải là số' })
  @Min(0, { message: 'Min price phải lớn hơn hoặc bằng 0' })
  @Type(() => Number)
  minPrice?: number;

  /**
   * Giá tối đa
   * VD: maxPrice=500000
   */
  @IsOptional()
  @IsNumber({}, { message: 'Max price phải là số' })
  @Min(0, { message: 'Max price phải lớn hơn hoặc bằng 0' })
  @Type(() => Number)
  maxPrice?: number;

  // ========== SORTING ==========

  /**
   * Sắp xếp theo field nào
   * Các giá trị: createdAt, updatedAt, currentPrice, originalPrice, status, typeAccount
   */
  @IsOptional()
  @IsEnum(
    [
      'createdAt',
      'updatedAt',
      'currentPrice',
      'originalPrice',
      'status',
      'typeAccount',
    ],
    {
      message:
        'Sort by phải là: createdAt, updatedAt, currentPrice, originalPrice, status, hoặc typeAccount',
    },
  )
  sortBy?:
    | 'createdAt'
    | 'updatedAt'
    | 'currentPrice'
    | 'originalPrice'
    | 'status'
    | 'typeAccount' = 'createdAt';

  /**
   * Thứ tự sắp xếp: ASC (tăng dần) hoặc DESC (giảm dần)
   */
  @IsOptional()
  @IsEnum(['ASC', 'DESC'], {
    message: 'Sort order phải là: ASC hoặc DESC',
  })
  sortOrder?: 'ASC' | 'DESC' = 'DESC';
}
