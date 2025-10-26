import { IsEnum, IsNotEmpty } from 'class-validator';

/**
 * DTO for Admin to update Request Deposit status
 */
export class UpdateRequestDepositDto {
  @IsNotEmpty({ message: 'Status is required' })
  @IsEnum(['pending', 'approved', 'rejected'], {
    message: 'Status must be pending, approved, or rejected',
  })
  status: 'pending' | 'approved' | 'rejected';
}
