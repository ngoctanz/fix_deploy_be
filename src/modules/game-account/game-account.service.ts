import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { GameAccountEntity } from '~/entities/game-account.entity';
import { ImageEntity } from '~/entities/image.entity';
import { GameCategoryEntity } from '~/entities/game-category.entity';
import { CloudinaryService } from '../cloudinary/cloudinary.service';
import { CreateGameAccountDto } from '~/dto/create-game-account.dto';
import { UpdateGameAccountDto } from '~/dto/update-game-account.dto';
import { FilterGameAccountDto } from '~/dto/filter-game-account.dto';
import { PaginatedResponseDto } from '~/dto/game-account.response.dto';

@Injectable()
export class GameAccountService {
  constructor(
    @InjectRepository(GameAccountEntity)
    private readonly gameAccountRepository: Repository<GameAccountEntity>,

    @InjectRepository(ImageEntity)
    private readonly imageRepository: Repository<ImageEntity>,

    @InjectRepository(GameCategoryEntity)
    private readonly gameCategoryRepository: Repository<GameCategoryEntity>,

    private readonly cloudinaryService: CloudinaryService,
  ) {}

  /**
   * TẠO GAME ACCOUNT MỚI
   * Upload ảnh chính + ảnh phụ lên Cloudinary
   */
  async create(
    createDto: CreateGameAccountDto,
    mainImage: Express.Multer.File,
    additionalImages?: Express.Multer.File[],
  ): Promise<GameAccountEntity> {
    // Kiểm tra game category có tồn tại không
    const category = await this.gameCategoryRepository.findOne({
      where: { gameCategoryId: createDto.gameCategoryId },
    });

    if (!category) {
      throw new BadRequestException(
        `Game category ID ${createDto.gameCategoryId} not found`,
      );
    }

    // Upload ảnh chính lên Cloudinary
    const mainImageResult = await this.cloudinaryService.uploadImage(
      mainImage,
      'game-accounts/main',
    );

    // Tạo game account
    const gameAccount = this.gameAccountRepository.create({
      ...createDto,
      mainImageUrl: mainImageResult.url,
      status: createDto.status || 'available',
      typeAccount: createDto.typeAccount || 'Normal',
    });

    const savedAccount = await this.gameAccountRepository.save(gameAccount);

    // Upload ảnh phụ nếu có
    if (additionalImages && additionalImages.length > 0) {
      const uploadedImages = await this.cloudinaryService.uploadMultipleImages(
        additionalImages,
        'game-accounts/additional',
      );

      // Lưu vào DB
      const imageEntities = uploadedImages.map((img, index) =>
        this.imageRepository.create({
          imageUrl: img.url,
          imageName: `${savedAccount.gameAccountId}_img_${index + 1}`,
          gameAccountId: savedAccount.gameAccountId,
        }),
      );

      await this.imageRepository.save(imageEntities);
    }

    // Return với relations
    const result = await this.gameAccountRepository.findOne({
      where: { gameAccountId: savedAccount.gameAccountId },
      relations: ['images', 'gameCategory'],
    });

    return result!;
  }

  /**
   * LẤY DANH SÁCH GAME ACCOUNTS
   * Có pagination, filtering, sorting
   */
  async findAll(
    filterDto: FilterGameAccountDto,
  ): Promise<PaginatedResponseDto<GameAccountEntity>> {
    const {
      page = 1,
      limit = 10,
      gameCategoryId,
      status,
      typeAccount,
      search,
      minPrice,
      maxPrice,
      sortBy = 'createdAt',
      sortOrder = 'DESC',
    } = filterDto;

    // Tạo query builder để có thể filter động
    const queryBuilder = this.gameAccountRepository
      .createQueryBuilder('account')
      .leftJoinAndSelect('account.gameCategory', 'category')
      .leftJoinAndSelect('account.images', 'images');

    // FILTERING
    if (gameCategoryId) {
      queryBuilder.andWhere('account.gameCategoryId = :gameCategoryId', {
        gameCategoryId,
      });
    }

    if (status) {
      queryBuilder.andWhere('account.status = :status', { status });
    }

    if (typeAccount) {
      queryBuilder.andWhere('account.typeAccount = :typeAccount', {
        typeAccount,
      });
    }

    // Tìm kiếm trong description
    if (search) {
      queryBuilder.andWhere('account.description LIKE :search', {
        search: `%${search}%`,
      });
    }

    // Lọc theo khoảng giá
    if (minPrice !== undefined && maxPrice !== undefined) {
      queryBuilder.andWhere(
        'account.currentPrice BETWEEN :minPrice AND :maxPrice',
        { minPrice, maxPrice },
      );
    } else if (minPrice !== undefined) {
      queryBuilder.andWhere('account.currentPrice >= :minPrice', { minPrice });
    } else if (maxPrice !== undefined) {
      queryBuilder.andWhere('account.currentPrice <= :maxPrice', { maxPrice });
    }

    // SORTING
    queryBuilder.orderBy(`account.${sortBy}`, sortOrder);

    // PAGINATION
    const skip = (page - 1) * limit;
    queryBuilder.skip(skip).take(limit);

    // Execute query
    const [data, total] = await queryBuilder.getManyAndCount();

    return new PaginatedResponseDto(data, page, limit, total);
  }

  /**
   * LẤY 1 GAME ACCOUNT THEO ID
   */
  async findOne(id: number): Promise<GameAccountEntity> {
    const gameAccount = await this.gameAccountRepository.findOne({
      where: { gameAccountId: id },
      relations: ['images', 'gameCategory'],
    });

    if (!gameAccount) {
      throw new NotFoundException(`Game account ID ${id} not found`);
    }

    return gameAccount;
  }

  /**
   * CẬP NHẬT GAME ACCOUNT
   * Hỗ trợ:
   * - Cập nhật thông tin
   * - Xóa ảnh cũ (DB + Cloudinary)
   * - Thêm ảnh mới
   * - Thay ảnh chính
   */
  async update(
    id: number,
    updateDto: UpdateGameAccountDto,
    newMainImage?: Express.Multer.File,
    newAdditionalImages?: Express.Multer.File[],
  ): Promise<GameAccountEntity> {
    const gameAccount = await this.gameAccountRepository.findOne({
      where: { gameAccountId: id },
    });

    if (!gameAccount) {
      throw new NotFoundException(`Game account ID ${id} not found`);
    }

    // Kiểm tra category nếu có thay đổi
    if (
      updateDto.gameCategoryId &&
      updateDto.gameCategoryId !== gameAccount.gameCategoryId
    ) {
      const category = await this.gameCategoryRepository.findOne({
        where: { gameCategoryId: updateDto.gameCategoryId },
      });

      if (!category) {
        throw new BadRequestException(
          `Game category ID ${updateDto.gameCategoryId} not found`,
        );
      }
    }

    // XÓA ẢNH PHỤ CŨ (nếu frontend yêu cầu)
    if (updateDto.deleteImageIds && updateDto.deleteImageIds.length > 0) {
      const imagesToDelete = await this.imageRepository.find({
        where: { imageId: In(updateDto.deleteImageIds) },
      });

      // Xóa trên Cloudinary
      const publicIds = imagesToDelete.map((img) =>
        this.cloudinaryService.extractPublicId(img.imageUrl),
      );
      await this.cloudinaryService.deleteMultipleImages(publicIds);

      // Xóa trong DB
      await this.imageRepository.remove(imagesToDelete);
    }

    // THAY ẢNH CHÍNH (nếu có)
    if (newMainImage) {
      // Xóa ảnh chính cũ trên Cloudinary
      if (gameAccount.mainImageUrl) {
        const oldPublicId = this.cloudinaryService.extractPublicId(
          gameAccount.mainImageUrl,
        );
        await this.cloudinaryService.deleteImage(oldPublicId);
      }

      // Upload ảnh chính mới
      const mainImageResult = await this.cloudinaryService.uploadImage(
        newMainImage,
        'game-accounts/main',
      );
      gameAccount.mainImageUrl = mainImageResult.url;
    }

    // CẬP NHẬT THÔNG TIN GAME ACCOUNT
    // Chỉ update các field được phép, không động vào relations
    const {
      gameCategoryId,
      originalPrice,
      currentPrice,
      description,
      status,
      typeAccount,
    } = updateDto;

    // Chỉ assign các field đã được destructure (loại bỏ images, deleteImageIds, và các field không mong muốn)
    if (gameCategoryId !== undefined)
      gameAccount.gameCategoryId = gameCategoryId;
    if (originalPrice !== undefined) gameAccount.originalPrice = originalPrice;
    if (currentPrice !== undefined) gameAccount.currentPrice = currentPrice;
    if (description !== undefined) gameAccount.description = description;
    if (status !== undefined) gameAccount.status = status;
    if (typeAccount !== undefined) gameAccount.typeAccount = typeAccount;

    // LƯU GAME ACCOUNT TRƯỚC (không có relations nên không bị conflict)
    await this.gameAccountRepository.save(gameAccount);

    // THÊM ẢNH PHỤ MỚI SAU KHI ĐÃ LƯU ACCOUNT (nếu có)
    if (newAdditionalImages && newAdditionalImages.length > 0) {
      const uploadedImages = await this.cloudinaryService.uploadMultipleImages(
        newAdditionalImages,
        'game-accounts/additional',
      );

      const imageEntities = uploadedImages.map((img, index) =>
        this.imageRepository.create({
          imageUrl: img.url,
          imageName: `${gameAccount.gameAccountId}_img_${Date.now()}_${index}`,
          gameAccountId: gameAccount.gameAccountId,
        }),
      );

      await this.imageRepository.save(imageEntities);
    }

    // Return với relations
    return this.findOne(id);
  }

  /**
   * XÓA GAME ACCOUNT
   * Xóa tất cả ảnh liên quan trên Cloudinary và DB
   */
  async remove(id: number): Promise<void> {
    const gameAccount = await this.findOne(id);
    if (gameAccount.orders && gameAccount.orders.length > 0) {
      throw new BadRequestException(
        'Không thể xoá vì tài khoản này đã có đơn hàng!',
      );
    }
    // Xóa ảnh chính trên Cloudinary
    if (gameAccount.mainImageUrl) {
      const mainPublicId = this.cloudinaryService.extractPublicId(
        gameAccount.mainImageUrl,
      );
      await this.cloudinaryService.deleteImage(mainPublicId);
    }

    // Xóa ảnh phụ trên Cloudinary
    if (gameAccount.images && gameAccount.images.length > 0) {
      const publicIds = gameAccount.images.map((img) =>
        this.cloudinaryService.extractPublicId(img.imageUrl),
      );
      await this.cloudinaryService.deleteMultipleImages(publicIds);

      // Xóa trong DB
      await this.imageRepository.remove(gameAccount.images);
    }

    // Xóa game account
    await this.gameAccountRepository.remove(gameAccount);
  }

  /**
   * Thống kê tổng số tài khoản và số tài khoản đã bán theo type (VIP, Normal)
   */
  async getStatsByType(gameCategoryId?: number): Promise<any[]> {
    const allAccounts = await this.gameAccountRepository.find({
      select: ['gameCategoryId', 'typeAccount', 'status'],
    });

    const types = ['VIP', 'Normal'];

    const filtered =
      typeof gameCategoryId === 'number'
        ? allAccounts.filter((acc) => acc.gameCategoryId === gameCategoryId)
        : allAccounts;

    return types.map((type) => {
      const accounts = filtered.filter((acc) => acc.typeAccount === type);
      const sold = accounts.filter((acc) => acc.status === 'sold');
      const available = accounts.filter((acc) => acc.status === 'available');
      return {
        typeAccount: type,
        sold: sold.length,
        available: available.length,
      };
    });
  }
}
