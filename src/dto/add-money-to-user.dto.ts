import { IsNotEmpty, IsNumber, Min } from 'class-validator';

/**
 * DTO for Admin to add money to User account
 */
export class AddMoneyToUserDto {
  @IsNotEmpty({ message: 'User ID is required' })
  @IsNumber({}, { message: 'User ID must be a number' })
  userId: number;

  @IsNotEmpty({ message: 'Amount is required' })
  @IsNumber({}, { message: 'Amount must be a number' })
  @Min(1, { message: 'Minimum amount is $1' })
  amount: number;
}
