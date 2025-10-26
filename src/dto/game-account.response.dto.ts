/**
 * Paginated Response DTO
 * Cấu trúc chuẩn cho response có phân trang
 */
export class PaginatedResponseDto<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };

  constructor(data: T[], page: number, limit: number, total: number) {
    this.data = data;
    this.pagination = {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    };
  }
}

/**
 * Game Account Response DTO
 * Cấu trúc response cho Game Account với thông tin đầy đủ
 */
export class GameAccountResponseDto {
  gameAccountId: number;
  status: string;
  gameCategoryId: number;
  gameCategoryName?: string; // Tên category (nếu join)
  originalPrice: number;
  currentPrice: number;
  description: string;
  mainImageUrl: string;
  typeAccount: string;
  createdAt: Date;
  updatedAt: Date;
  images?: ImageResponseDto[]; // Danh sách ảnh phụ
}

/**
 * Image Response DTO
 */
export class ImageResponseDto {
  imageId: number;
  imageUrl: string;
  imageName: string;
}
