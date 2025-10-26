/**
 * Response DTO khi đăng nhập/đăng ký thành công
 * Chứa thông tin user (không bao gồm password)
 */
export class AuthResponseDto {
  userId: number;
  email: string;
  money: number;
  role: 'USER' | 'ADMIN';
  message: string;
}
