import { ConfigService } from '@nestjs/config';

export const envConfig = (configService: ConfigService) => ({
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
    accessExpiration: configService.get<string>('JWT_ACCESS_EXPIRATION', '30m'),
    refreshExpiration: configService.get<string>(
      'JWT_REFRESH_EXPIRATION',
      '7d',
    ),
  },
  // Cookie Configuration
  cookie: {
    // Tự động set secure=true khi dùng HTTPS hoặc khi sameSite='none'
    // Quan trọng: sameSite='none' BẮT BUỘC phải có secure=true
    secure:
      configService.get<string>('DOMAIN_FRONTEND', '').startsWith('https') ||
      configService.get<string>('COOKIE_SAME_SITE', 'none') === 'none' ||
      configService.get<string>('NODE_ENV') === 'production',
    // sameSite='none' cho phép cross-domain (FE và BE khác domain)
    // sameSite='lax' nếu FE và BE cùng domain
    sameSite: configService.get<'lax' | 'strict' | 'none'>(
      'COOKIE_SAME_SITE',
      'none', // Mặc định 'none' để hoạt động với mọi trường hợp deploy
    ),
    accessMaxAge: 30 * 60 * 1000, // 30 phút
    refreshMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
  },
  // Application Configuration
  app: {
    nodeEnv: configService.get<string>('NODE_ENV', 'development'),
    port: configService.get<number>('PORT', 3001),
    isProduction: configService.get<string>('NODE_ENV') === 'production',
    isDevelopment: configService.get<string>('NODE_ENV') === 'development',
  },
});
