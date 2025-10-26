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
   * - Kiểm tra email đã tồn tại chưa
   * - Hash password bằng bcrypt (10 rounds)
   * - Tạo user mới trong database
   * - Tự động đăng nhập (generate tokens)
   */
  async register(registerDto: RegisterDto, response: Response) {
    // Kiểm tra email đã tồn tại
    const existingUser = await this.userRepository.findOne({
      where: { email: registerDto.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    // Hash password với bcrypt (10 salt rounds)
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    // Tạo user mới
    const newUser = this.userRepository.create({
      email: registerDto.email,
      password: hashedPassword,
      money: 0,
      role: 'USER',
    });

    const savedUser = await this.userRepository.save(newUser);

    // Tự động login sau khi đăng ký
    return this.login(savedUser, response);
  }

  async login(user: UserEntity, response: Response) {
    const config = envConfig(this.configService);

    // Payload chứa thông tin user trong token
    const payload = {
      sub: user.userId, // 'sub' là convention của JWT cho user ID
      email: user.email,
      money: user.money,
      role: user.role,
    };

    // Tạo Access Token (thời hạn ngắn: 30 phút)
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: config.jwt.accessSecret,
      expiresIn: config.jwt.accessExpiration,
    } as any);

    // Tạo Refresh Token (thời hạn dài: 7 ngày)
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: config.jwt.refreshSecret,
      expiresIn: config.jwt.refreshExpiration,
    } as any);

    // Hash refresh token trước khi lưu vào DB (bảo mật)
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    // Lưu hashed refresh token vào DB
    await this.userRepository.update(user.userId, {
      refreshToken: hashedRefreshToken,
    });

    response.cookie('accessToken', accessToken, {
      httpOnly: true, // Không thể truy cập từ JavaScript (chống XSS)
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      maxAge: config.cookie.accessMaxAge,
    });

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      maxAge: config.cookie.refreshMaxAge,
    });

    return {
      message: 'Login successful',
    };
  }

  /**
   * Lấy user theo userId
   */
  async getUserById(userId: number): Promise<UserEntity | null> {
    return await this.userRepository.findOne({ where: { userId } });
  }

  /**
   * VALIDATE USER (dùng cho Local Strategy)
   * - Tìm user theo email
   * - So sánh password với hash trong DB
   */
  async validateUser({ email, password }: { email: string; password: string }) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      return null;
    }

    // So sánh password với hash trong DB
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      return user;
    }

    return null;
  }

  /**
   * REFRESH ACCESS TOKEN
   * - Lấy refreshToken từ cookie
   * - Verify refreshToken
   * - Kiểm tra refreshToken có khớp với hash trong DB không
   * - Tạo accessToken mới
   */
  async refreshAccessToken(refreshToken: string, response: Response) {
    const config = envConfig(this.configService);

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken, {
        secret: config.jwt.refreshSecret,
      });

      // Tìm user trong DB
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

      // Tạo access token mới
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

      // Set access token mới vào cookie
      response.cookie('accessToken', newAccessToken, {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        maxAge: config.cookie.accessMaxAge,
      });

      return {
        message: 'Refresh token successful',
      };
    } catch (error) {
      throw new UnauthorizedException(
        error + 'Invalid or expired refresh token',
      );
    }
  }

  async logout(userId: number, response: Response) {
    // Xóa refresh token trong DB
    await this.userRepository.update(userId, {
      refreshToken: null,
    });

    response.clearCookie('accessToken');
    response.clearCookie('refreshToken');

    return {
      message: 'Logout successful',
    };
  }
}
