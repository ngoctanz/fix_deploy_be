import { IsString, IsNotEmpty, MinLength, Matches } from 'class-validator';

/**
 * DTO for User to update their own password
 */
export class ChangePasswordDto {
  @IsNotEmpty({ message: 'Old password is required' })
  @IsString()
  oldPassword: string;

  @IsNotEmpty({ message: 'New password is required' })
  @IsString()
  @MinLength(6, { message: 'New password must be at least 6 characters' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)/, {
    message: 'New password must contain at least 1 letter and 1 number',
  })
  newPassword: string;
}
