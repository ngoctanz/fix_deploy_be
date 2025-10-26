import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserEntity } from '~/entities/user.entity';
import * as bcrypt from 'bcrypt';
import { ChangePasswordDto } from '~/dto/change-password.dto';
import { FilterUserDto } from '~/dto/filter-user.dto';
import { UpdateUserDto } from '~/dto/update-user.dto';

/**
 * USER SERVICE
 * Xử lý logic nghiệp vụ cho User
 */
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
  ) {}

  /**
   * ADMIN - Lấy danh sách tất cả users với phân trang và filter
   */
  async findAll(filterDto: FilterUserDto): Promise<{
    data: UserEntity[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const { page = 1, limit = 10, role, search } = filterDto;

    const queryBuilder = this.userRepository
      .createQueryBuilder('user')
      .select([
        'user.userId',
        'user.email',
        'user.money',
        'user.role',
        'user.createdAt',
        'user.updatedAt',
      ]); // Không select password

    // Filter theo role nếu có
    if (role) {
      queryBuilder.andWhere('user.role = :role', { role });
    }

    // Tìm kiếm theo email nếu có
    if (search) {
      queryBuilder.andWhere('user.email ILIKE :search', {
        search: `%${search}%`,
      });
    }

    // Sắp xếp theo createdAt DESC (mới nhất trước)
    queryBuilder.orderBy('user.createdAt', 'DESC');

    // Đếm tổng số records
    const total = await queryBuilder.getCount();

    // Phân trang
    const skip = (page - 1) * limit;
    queryBuilder.skip(skip).take(limit);

    // Lấy data
    const data = await queryBuilder.getMany();

    return {
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Tạo user mới (internal use - được gọi từ AuthService)
   */
  async create(userData: Partial<UserEntity>): Promise<UserEntity> {
    const hashPassword = await bcrypt.hash(userData.password!, 10);

    const user = this.userRepository.create({
      ...userData,
      password: hashPassword,
    });
    return this.userRepository.save(user);
  }

  /**
   * Tìm user theo userId
   */
  async findById(userId: number): Promise<UserEntity | null> {
    const user = await this.userRepository.findOneBy({ userId });

    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    return user;
  }

  /**
   * USER - Tự cập nhật mật khẩu của mình
   */
  async changePassword(
    userId: number,
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({
      where: { userId },
      select: ['userId', 'email', 'password'], // Cần select password để verify
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify mật khẩu cũ
    const isOldPasswordValid = await bcrypt.compare(
      changePasswordDto.oldPassword,
      user.password,
    );

    if (!isOldPasswordValid) {
      throw new BadRequestException('Old password is incorrect');
    }

    // Hash mật khẩu mới
    const hashedNewPassword = await bcrypt.hash(
      changePasswordDto.newPassword,
      10,
    );

    // Update mật khẩu
    await this.userRepository.update(userId, {
      password: hashedNewPassword,
    });

    return { message: 'Password changed successfully' };
  }

  /**
   * ADMIN - Xóa user
   */
  async delete(userId: number): Promise<void> {
    const user = await this.findById(userId);
    await this.userRepository.remove(user!); // Đã check exists trong findById
  }

  /**
   * ADMIN - Cập nhật thông tin user
   */
  async update(
    userId: number,
    updateUserDto: UpdateUserDto,
  ): Promise<UserEntity> {
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    user.email = updateUserDto.email;
    user.role = updateUserDto.role as 'USER' | 'ADMIN';
    user.money = updateUserDto.money;
    user.updatedAt = new Date();
    await this.userRepository.save(user);
    return user;
  }
}
