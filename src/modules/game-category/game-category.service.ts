import {
  Injectable,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { GameCategoryEntity } from '~/entities/game-category.entity';
import { GameCategoryListResponseDto } from '~/dto/game-category-list-response.dto';
import { CreateGameCategoryDto } from '~/dto/create-game-category.dto';
import { UpdateGameCategoryDto } from '~/dto/update-game-category.dto';
import { CloudinaryService } from '../cloudinary/cloudinary.service';

@Injectable()
export class GameCategoryService {
  constructor(
    @InjectRepository(GameCategoryEntity)
    private readonly gameCategoryRepository: Repository<GameCategoryEntity>,
    private readonly cloudinaryService: CloudinaryService,
  ) {}

  async findAll(): Promise<GameCategoryListResponseDto[]> {
    const categories = await this.gameCategoryRepository.find({
      relations: ['gameAccounts'],
      order: { gameCategoryId: 'DESC' },
    });

    return categories.map((cat) => ({
      gameCategoryId: cat.gameCategoryId,
      gameCategoryName: cat.gameCategoryName,
      imageGameCategory: cat.imageGameCategory,
      availableAccounts: cat.gameAccounts.filter(
        (acc) => acc.status === 'available',
      ).length,
      soldAccounts: cat.gameAccounts.filter((acc) => acc.status === 'sold')
        .length,
    }));
  }

  /**
   * Lấy 1 danh mục game theo ID
   * PUBLIC - Ai cũng có thể xem
   */
  async findOne(id: number): Promise<GameCategoryEntity> {
    const category = await this.gameCategoryRepository.findOne({
      where: { gameCategoryId: id },
      relations: ['gameAccounts'],
    });

    if (!category) {
      throw new NotFoundException(`Game category with ID ${id} not found`);
    }

    return category;
  }

  /**
   * Tạo danh mục game mới
   * CHỈ ADMIN - Yêu cầu role ADMIN
   */
  async create(
    createDto: CreateGameCategoryDto,
    imageFile?: Express.Multer.File,
  ): Promise<GameCategoryEntity> {
    // Kiểm tra tên danh mục đã tồn tại chưa
    const existingCategory = await this.gameCategoryRepository.findOne({
      where: { gameCategoryName: createDto.gameCategoryName },
    });

    if (existingCategory) {
      throw new ConflictException(
        `Game category "${createDto.gameCategoryName}" already exists`,
      );
    }

    // Upload ảnh lên Cloudinary nếu có
    let imageUrl: string | undefined;
    if (imageFile) {
      const uploadResult = await this.cloudinaryService.uploadImage(
        imageFile,
        'game-categories',
      );
      imageUrl = uploadResult.url;
    }

    // Tạo mới category với URL ảnh từ Cloudinary
    const category = this.gameCategoryRepository.create({
      ...createDto,
      imageGameCategory: imageUrl || createDto.imageGameCategory,
    });

    return this.gameCategoryRepository.save(category);
  }

  /**
   * Cập nhật danh mục game
   * CHỈ ADMIN - Yêu cầu role ADMIN
   */
  async update(
    id: number,
    updateDto: UpdateGameCategoryDto,
    newImageFile?: Express.Multer.File,
  ): Promise<GameCategoryEntity> {
    // Tìm category hiện tại
    const category = await this.findOne(id);

    // Kiểm tra tên danh mục đã tồn tại chưa
    if (updateDto.gameCategoryName) {
      const existingCategory = await this.gameCategoryRepository.findOne({
        where: { gameCategoryName: updateDto.gameCategoryName },
      });

      if (existingCategory && existingCategory.gameCategoryId !== id) {
        throw new ConflictException(
          `Game category "${updateDto.gameCategoryName}" already exists`,
        );
      }
    }

    // Xử lý ảnh mới nếu có
    let newImageUrl: string | undefined;
    if (newImageFile) {
      // Upload ảnh mới lên Cloudinary
      const uploadResult = await this.cloudinaryService.uploadImage(
        newImageFile,
        'game-categories',
      );
      newImageUrl = uploadResult.url;

      // Xóa ảnh cũ trên Cloudinary nếu có
      if (category.imageGameCategory) {
        const publicId = this.cloudinaryService.extractPublicId(
          category.imageGameCategory,
        );
        if (publicId) {
          await this.cloudinaryService.deleteImage(publicId);
        }
      }
    }

    // Cập nhật category
    const updateData = {
      ...updateDto,
      ...(newImageUrl && { imageGameCategory: newImageUrl }),
    };

    await this.gameCategoryRepository.update(id, updateData);
    return this.findOne(id);
  }

  /**
   * Xóa danh mục game
   * CHỈ ADMIN - Yêu cầu role ADMIN
   * Xóa ảnh trên Cloudinary trước khi xóa khỏi database
   */
  async remove(id: number): Promise<void> {
    const category = await this.findOne(id);

    // Xóa ảnh trên Cloudinary nếu có
    if (category.imageGameCategory) {
      const publicId = this.cloudinaryService.extractPublicId(
        category.imageGameCategory,
      );
      if (publicId) {
        await this.cloudinaryService.deleteImage(publicId);
      }
    }

    // Xóa category khỏi database
    await this.gameCategoryRepository.remove(category);
  }
}
