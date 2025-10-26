import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { envConfig } from '~/config/env.config';

/**
 * JWT STRATEGY - Hỗ trợ cả cookie và header Bearer
 *
 * Cách hoạt động:
 * 1️⃣ Ưu tiên lấy JWT từ cookie 'accessToken' (bảo mật nhất)
 * 2️⃣ Nếu cookie không tồn tại (ví dụ Safari iOS), fallback sang Authorization header
 * 3️⃣ Verify token bằng secret key
 * 4️⃣ Nếu hợp lệ → trả về payload -> req.user
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    const config = envConfig(configService);

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // 1️⃣ Lấy từ cookie
        (req: Request) => req?.cookies?.accessToken,
        // 2️⃣ Fallback: lấy từ header Authorization: Bearer <token>
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: config.jwt.accessSecret,
    });
  }

  async validate(payload: any) {
    // payload = { sub, email, money, role, iat, exp }
    if (!payload?.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      money: payload.money,
      role: payload.role,
    };
  }
}
