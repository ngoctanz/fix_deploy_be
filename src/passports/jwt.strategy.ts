import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { envConfig } from '~/config/env.config';

/**
 * JWT STRATEGY - Xử lý authentication với JWT
 *
 * CÁCH HOẠT ĐỘNG:
 * 1. Khi client gửi request với JWT (trong cookie hoặc header)
 * 2. Strategy này sẽ extract JWT từ cookie 'accessToken'
 * 3. Verify JWT với secret key
 * 4. Nếu valid, gọi hàm validate() với decoded payload
 * 5. Return value của validate() sẽ được gán vào req.user
 * 6. Controller có thể access thông tin user qua req.user
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    const config = envConfig(configService);

    super({
      // Extract JWT từ cookie thay vì Authorization header
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          // Lấy token từ cookie 'accessToken'
          return request?.cookies?.accessToken;
        },
        // Fallback: nếu không có trong cookie, lấy từ Authorization header
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false, // Reject token đã hết hạn
      secretOrKey: config.jwt.accessSecret,
    });
  }

  /**
   * Hàm validate tự động được gọi sau khi JWT được verify thành công
   * @param payload - Decoded JWT payload chứa thông tin user
   * @returns Object sẽ được gán vào req.user
   */
  async validate(payload: any) {
    // payload chứa: { sub: userId, email, money, role, iat, exp }
    return {
      userId: payload.sub, // 'sub' là user ID
      email: payload.email,
      money: payload.money,
      role: payload.role,
    };
  }
}
