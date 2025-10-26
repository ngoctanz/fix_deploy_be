import { IsNotEmpty, IsNumber, IsInt } from 'class-validator';

/**
 * DTO để User mua Game Account
 */
export class PurchaseGameAccountDto {
  @IsNotEmpty({ message: 'Game Account ID không được để trống' })
  @IsNumber({}, { message: 'Game Account ID phải là số' })
  @IsInt({ message: 'Game Account ID phải là số nguyên' })
  gameAccountId: number;
}
