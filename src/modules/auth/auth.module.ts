import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '~/entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { envConfig } from '~/config/env.config';
import { LocalStrategy } from '~/passports/local.strategy';
import { JwtStrategy } from '~/passports/jwt.strategy';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy, // Strategy cho login (validate email/password)
    JwtStrategy, // Strategy cho protected routes (validate JWT)
  ],
  imports: [
    UserModule,
    TypeOrmModule.forFeature([UserEntity]),
    // Cấu hình JWT Module với ConfigService
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const config = envConfig(configService);
        return {
          secret: config.jwt.accessSecret,
          signOptions: {
            expiresIn: config.jwt.accessExpiration,
          } as any,
        };
      },
      inject: [ConfigService],
    }),
  ],
})
export class AuthModule {}
