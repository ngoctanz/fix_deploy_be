import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * JWT AUTH GUARD - Guard kiểm tra người dùng đã đăng nhập chưa
 *
 * CÁCH HOẠT ĐỘNG:
 * 1. Guard này sử dụng JwtStrategy (trong src/passports/jwt.strategy.ts)
 * 2. JwtStrategy sẽ:
 *    - Lấy token từ req.cookies.accessToken
 *    - Verify token với secret key
 *    - Decode payload: { sub, email, role, money }
 *    - Gọi validate() để transform payload
 *    - Return object sẽ được gán vào req.user
 *
 * SAU KHI GUARD NÀY CHẠY XONG:
 * req.user = {
 *   userId: number,
 *   email: string,
 *   role: 'USER' | 'ADMIN',
 *   money: number
 * }
 *
 * CÁCH DÙNG:
 * @UseGuards(JwtAuthGuard)
 * myMethod(@Req() req) {
 *   const userId = req.user.userId; // ✅ Lấy được ID
 *   const email = req.user.email;   // ✅ Lấy được email
 *   const role = req.user.role;     // ✅ Lấy được role
 * }
 *
 * LƯU Ý:
 * - Token được lấy từ COOKIE (HttpOnly) → An toàn
 * - Không cần gửi token trong header Authorization
 * - Browser tự động gửi cookie kèm mỗi request
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
