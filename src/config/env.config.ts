import { ConfigService } from '@nestjs/config';

export const envConfig = (configService: ConfigService) => {
  const nodeEnv = configService.get<string>('NODE_ENV', 'development');
  const sameSite = configService.get<'lax' | 'strict' | 'none'>(
    'COOKIE_SAME_SITE',
    'none',
  );

  // Nếu chạy trên Render / Vercel => bắt buộc secure:true khi sameSite='none'
  const secure =
    sameSite === 'none' ||
    nodeEnv === 'production' ||
    configService.get<string>('DOMAIN_FRONTEND', '').startsWith('https');

  return {
    // Database Configuration
    database: {
      host: configService.get<string>('DB_HOST', 'localhost'),
      port: configService.get<number>('DB_PORT', 5432),
      username: configService.get<string>('DB_USERNAME', 'hieuvolaptrinh'),
      password: configService.get<string>('DB_PASSWORD', 'hieuvolaptrinh'),
      name: configService.get<string>('DB_DATABASE', 'game_account'),
    },

    // JWT Configuration
    jwt: {
      accessSecret: configService.get<string>(
        'JWT_ACCESS_SECRET',
        '3456uikjnaidhh891342536634twefsfefwt4363rqfegsrhdjyrerfssad',
      ),
      refreshSecret: configService.get<string>(
        'JWT_REFRESH_SECRET',
        'hieuvolaptrinhhieuvolaptrinhrq3HIUHN3I2U09OIH2222sdsdasd3lIOz',
      ),
      accessExpiration: configService.get<string>(
        'JWT_ACCESS_EXPIRATION',
        '30m',
      ),
      refreshExpiration: configService.get<string>(
        'JWT_REFRESH_EXPIRATION',
        '7d',
      ),
    },

    cookie: {
      secure, // ✅ ép true khi sameSite='none'
      sameSite, // ✅ cho phép cross-domain
      accessMaxAge: 30 * 60 * 1000, // 30 phút
      refreshMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
    },

    // Application Configuration
    app: {
      nodeEnv,
      port: configService.get<number>('PORT', 3001),
      isProduction: nodeEnv === 'production',
      isDevelopment: nodeEnv === 'development',
    },
  };
};
