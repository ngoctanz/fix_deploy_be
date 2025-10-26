import { IsNotEmpty, IsString, IsOptional } from 'class-validator';

/**
 * DTO for creating a new Request Deposit
 * User sends bill image + description to request deposit
 */
export class CreateRequestDepositDto {
  @IsNotEmpty({ message: 'Description is required' })
  @IsString({ message: 'Description must be a string' })
  description: string;

  // imgUrl will be set automatically after uploading image to Cloudinary
  @IsOptional()
  @IsString()
  imgUrl?: string;
}
