import { IsString, IsOptional } from 'class-validator';

/**
 * DTO for updating a Game Category
 */
export class UpdateGameCategoryDto {
  @IsOptional()
  @IsString({ message: 'Game category name must be a string' })
  gameCategoryName?: string;

  @IsOptional()
  @IsString({ message: 'Image URL must be a string' })
  imageGameCategory?: string;
}
