import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  HttpStatus,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { GameCategoryService } from './game-category.service';
import { CreateGameCategoryDto } from '~/dto/create-game-category.dto';
import { UpdateGameCategoryDto } from '~/dto/update-game-category.dto';
import { JwtAuthGuard } from '~/guard/jwt-auth.guard';
import { RolesGuard } from '~/guard/roles.guard';
import { Role, Roles } from '~/decorators/roles.decorator';
import { ResponseData } from '~/global/ResponseData';

/**
 * GAME CATEGORY CONTROLLER
 * Quản lý API cho danh mục game với Cloudinary upload
 */
@Controller('game-category')
export class GameCategoryController {
  constructor(private readonly gameCategoryService: GameCategoryService) {}

  @Get()
  async findAll() {
    const result = await this.gameCategoryService.findAll();
    return new ResponseData(
      HttpStatus.OK,
      'Categories retrieved successfully',
      result,
    );
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    const result = await this.gameCategoryService.findOne(+id);
    return new ResponseData(
      HttpStatus.OK,
      'Category details retrieved successfully',
      result,
    );
  }

  /**
   * Tạo danh mục game mới
   * CHỈ ADMIN - Yêu cầu role ADMIN
   * Upload ảnh với field name: "image"
   */
  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @UseInterceptors(FileInterceptor('image'))
  async create(
    @Body() createDto: CreateGameCategoryDto,
    @UploadedFile() image: Express.Multer.File,
  ) {
    const result = await this.gameCategoryService.create(createDto, image);
    return new ResponseData(
      HttpStatus.CREATED,
      'Category created successfully',
      result,
    );
  }

  /**
   * Cập nhật danh mục game
   * CHỈ ADMIN - Yêu cầu role ADMIN
   * Upload ảnh mới (optional) với field name: "newImage"
   */
  @Put(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @UseInterceptors(FileInterceptor('newImage'))
  async update(
    @Param('id') id: string,
    @Body() updateDto: UpdateGameCategoryDto,
    @UploadedFile() newImage: Express.Multer.File,
  ) {
    const result = await this.gameCategoryService.update(
      +id,
      updateDto,
      newImage,
    );
    return new ResponseData(
      HttpStatus.OK,
      'Category updated successfully',
      result,
    );
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async remove(@Param('id') id: string) {
    await this.gameCategoryService.remove(+id);
    return new ResponseData(
      HttpStatus.OK,
      'Category deleted successfully',
      null,
    );
  }
}
