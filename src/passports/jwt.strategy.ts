import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { envConfig } from '~/config/env.config';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    const config = envConfig(configService);

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // 1. Lấy từ cookie (desktop)
        (request: Request) => {
          return request?.cookies?.['accessToken'] || null;
        },
        // 2. Lấy từ Authorization header (iPhone/mobile)
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: config.jwt.accessSecret,
    });
  }

  async validate(payload: any) {
    if (!payload) {
      throw new UnauthorizedException('Invalid token');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      money: payload.money,
      role: payload.role,
    };
  }
}
