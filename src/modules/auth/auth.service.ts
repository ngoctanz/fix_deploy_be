import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '~/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from '~/dto/register.dto';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { envConfig } from '~/config/env.config';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * ĐĂNG KÝ USER MỚI
   */
  async register(registerDto: RegisterDto, response: Response) {
    const existingUser = await this.userRepository.findOne({
      where: { email: registerDto.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    const newUser = this.userRepository.create({
      email: registerDto.email,
      password: hashedPassword,
      money: 0,
      role: 'USER',
    });

    const savedUser = await this.userRepository.save(newUser);

    return this.login(savedUser, response);
  }

  /**
   * LOGIN
   */
  async login(user: UserEntity, response: Response) {
    const config = envConfig(this.configService);

    const payload = {
      sub: user.userId,
      email: user.email,
      money: user.money,
      role: user.role,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: config.jwt.accessSecret,
      expiresIn: config.jwt.accessExpiration,
    } as any);

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: config.jwt.refreshSecret,
      expiresIn: config.jwt.refreshExpiration,
    } as any);

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.userRepository.update(user.userId, {
      refreshToken: hashedRefreshToken,
    });

    // Cookie options nhất quán cho tất cả cookies
    const cookieOptions = {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite as 'lax' | 'strict' | 'none',
      path: '/',
    };

    response.cookie('accessToken', accessToken, {
      ...cookieOptions,
      maxAge: config.cookie.accessMaxAge,
    });

    response.cookie('refreshToken', refreshToken, {
      ...cookieOptions,
      maxAge: config.cookie.refreshMaxAge,
    });

    console.log('🍪 Cookie set with config:', {
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      nodeEnv: config.app.nodeEnv,
    });

    return {
      message: 'Login successful',
    };
  }

  /**
   * GET USER BY ID
   */
  async getUserById(userId: number): Promise<UserEntity | null> {
    return await this.userRepository.findOne({ where: { userId } });
  }

  /**
   * VALIDATE USER (Local Strategy)
   */
  async validateUser({ email, password }: { email: string; password: string }) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      return null;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      return user;
    }

    return null;
  }

  /**
   * REFRESH ACCESS TOKEN
   */
  async refreshAccessToken(refreshToken: string, response: Response) {
    const config = envConfig(this.configService);

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: config.jwt.refreshSecret,
      });

      const user = await this.userRepository.findOne({
        where: { userId: payload.sub },
      });

      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('User not found or already logged out');
      }

      const isRefreshTokenValid = await bcrypt.compare(
        refreshToken,
        user.refreshToken,
      );

      if (!isRefreshTokenValid) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const newPayload = {
        sub: user.userId,
        email: user.email,
        money: user.money,
        role: user.role,
      };

      const newAccessToken = await this.jwtService.signAsync(newPayload, {
        secret: config.jwt.accessSecret,
        expiresIn: config.jwt.accessExpiration,
      } as any);

      response.cookie('accessToken', newAccessToken, {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite as 'lax' | 'strict' | 'none',
        path: '/',
        maxAge: config.cookie.accessMaxAge,
      });

      return {
        message: 'Refresh token successful',
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  /**
   * LOGOUT
   */
  async logout(userId: number, response: Response) {
    const config = envConfig(this.configService);

    await this.userRepository.update(userId, {
      refreshToken: null,
    });

    // QUAN TRỌNG: clearCookie phải có ĐÚNG options như lúc set
    const cookieOptions = {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite as 'lax' | 'strict' | 'none',
      path: '/',
    };

    response.clearCookie('accessToken', cookieOptions);
    response.clearCookie('refreshToken', cookieOptions);

    console.log('🗑️ Cookies cleared with config:', cookieOptions);

    return {
      message: 'Logout successful',
    };
  }
}
