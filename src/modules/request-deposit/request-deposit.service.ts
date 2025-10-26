import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RequestDepositEntity } from '~/entities/request-deposit.entity';
import { UserEntity } from '~/entities/user.entity';
import { CloudinaryService } from '../cloudinary/cloudinary.service';
import { CreateRequestDepositDto } from '~/dto/create-request-deposit.dto';
import { FilterRequestDepositDto } from '~/dto/filter-request-deposit.dto';
import { UpdateRequestDepositDto } from '~/dto/update-request-deposit.dto';
import { AddMoneyToUserDto } from '~/dto/add-money-to-user.dto';

/**
 * SERVICE - Xử lý logic nghiệp vụ cho Request Deposit
 * User nạp tiền vào tài khoản bằng cách upload bill chuyển khoản
 * Admin duyệt yêu cầu và cộng tiền vào tài khoản user
 */
@Injectable()
export class RequestDepositService {
  constructor(
    @InjectRepository(RequestDepositEntity)
    private readonly requestDepositRepository: Repository<RequestDepositEntity>,

    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,

    private readonly cloudinaryService: CloudinaryService,
  ) {}

  /**
   * USER - Tạo yêu cầu nạp tiền mới
   * Upload ảnh bill lên Cloudinary và lưu vào DB
   */
  async create(
    userId: number,
    createDto: CreateRequestDepositDto,
    imageFile: Express.Multer.File,
  ): Promise<RequestDepositEntity> {
    // Upload ảnh bill lên Cloudinary
    const uploadResult = await this.cloudinaryService.uploadImage(
      imageFile,
      'deposit-bills', // folder trên Cloudinary
    );

    // Tạo request deposit mới
    const requestDeposit = this.requestDepositRepository.create({
      userId,
      description: createDto.description,
      imgUrl: uploadResult.url,
      status: 'pending', // Mặc định là pending
    });

    return this.requestDepositRepository.save(requestDeposit);
  }

  /**
   * ADMIN - Lấy tất cả yêu cầu nạp tiền với phân trang và lọc
   * Mặc định sắp xếp: pending lên đầu, sau đó theo createdAt DESC
   */
  async findAll(filterDto: FilterRequestDepositDto): Promise<{
    data: RequestDepositEntity[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const { page = 1, limit = 10, status, userId } = filterDto;

    const queryBuilder = this.requestDepositRepository
      .createQueryBuilder('request')
      .leftJoinAndSelect('request.user', 'user') // Join để lấy email của user
      .select([
        'request.requestDepositId',
        'request.userId',
        'request.description',
        'request.imgUrl',
        'request.status',
        'request.createdAt',
        'user.userId',
        'user.email', // Lấy email của user
        'user.money', // Lấy số tiền hiện tại của user
      ]);

    // Filter theo status nếu có
    if (status) {
      queryBuilder.andWhere('request.status = :status', { status });
    }

    // Filter theo userId nếu có
    if (userId) {
      queryBuilder.andWhere('request.userId = :userId', { userId });
    }

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
   * USER - Lấy tất cả yêu cầu của chính mình
   */
  async findMyRequests(
    userId: number,
    filterDto: FilterRequestDepositDto,
  ): Promise<{
    data: RequestDepositEntity[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const { page = 1, limit = 10, status } = filterDto;

    const queryBuilder = this.requestDepositRepository
      .createQueryBuilder('request')
      .where('request.userId = :userId', { userId });

    // Filter theo status nếu có
    if (status) {
      queryBuilder.andWhere('request.status = :status', { status });
    }

    // Sắp xếp: pending lên đầu, sau đó theo createdAt DESC
    queryBuilder
      .addOrderBy(
        `CASE WHEN request.status = 'pending' THEN 0 ELSE 1 END`,
        'ASC',
      )
      .addOrderBy('request.createdAt', 'DESC');

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
   * ADMIN - Lấy chi tiết 1 yêu cầu theo ID (kèm thông tin user)
   */
  async findOne(id: number): Promise<RequestDepositEntity> {
    const request = await this.requestDepositRepository.findOne({
      where: { requestDepositId: id },
      relations: ['user'],
    });

    if (!request) {
      throw new NotFoundException(`Request with ID ${id} not found`);
    }

    return request;
  }

  /**
   * ADMIN - Cập nhật trạng thái yêu cầu nạp tiền
   * Chỉ update status (approved/rejected/pending)
   */
  async updateStatus(
    id: number,
    updateDto: UpdateRequestDepositDto,
  ): Promise<RequestDepositEntity> {
    const request = await this.findOne(id);

    // Update status
    request.status = updateDto.status;
    return this.requestDepositRepository.save(request);
  }

  /**
   * ADMIN - Cộng tiền vào tài khoản user
   * Được gọi sau khi admin approve request deposit
   */
  async addMoneyToUser(addMoneyDto: AddMoneyToUserDto): Promise<UserEntity> {
    const { userId, amount } = addMoneyDto;

    // Tìm user
    const user = await this.userRepository.findOne({
      where: { userId },
    });

    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    // Cộng tiền vào tài khoản
    user.money = Number(user.money) + Number(amount);

    return this.userRepository.save(user);
  }

  /**
   * ADMIN - Xóa yêu cầu nạp tiền
   * Xóa cả ảnh trên Cloudinary
   */
  async remove(id: number): Promise<void> {
    const request = await this.findOne(id);

    // Xóa ảnh trên Cloudinary nếu có
    if (request.imgUrl) {
      const publicId = this.cloudinaryService.extractPublicId(request.imgUrl);
      if (publicId) {
        await this.cloudinaryService.deleteImage(publicId);
      }
    }

    // Xóa request khỏi DB
    await this.requestDepositRepository.remove(request);
  }

  // Tạo api để lấy danh sách yêu cầu nạp tiền của user
  async findAllByUserId(userId: number) {
    return this.requestDepositRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }
}
