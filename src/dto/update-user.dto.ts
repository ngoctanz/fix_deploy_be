import { IsEmail, IsNotEmpty, IsNumber } from 'class-validator';

export class UpdateUserDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;
  @IsNotEmpty()
  role: string;
  @IsNotEmpty()
  @IsNumber()
  money: number;
}
