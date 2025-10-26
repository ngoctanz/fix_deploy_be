import { IsNotEmpty, IsString, IsOptional } from 'class-validator';

/**
 * DTO for creating a new Game Category
 */
export class CreateGameCategoryDto {
  @IsNotEmpty({ message: 'Game category name is required' })
  @IsString({ message: 'Game category name must be a string' })
  gameCategoryName: string;

  @IsOptional()
  @IsString({ message: 'Image URL must be a string' })
  imageGameCategory?: string;
}
