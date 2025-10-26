import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  UseInterceptors,
  UploadedFiles,
  HttpStatus,
  ParseIntPipe,
} from '@nestjs/common';
import { FileFieldsInterceptor } from '@nestjs/platform-express';
import { GameAccountService } from './game-account.service';
import { CreateGameAccountDto } from '~/dto/create-game-account.dto';
import { UpdateGameAccountDto } from '~/dto/update-game-account.dto';
import { FilterGameAccountDto } from '~/dto/filter-game-account.dto';
import { JwtAuthGuard } from '~/guard/jwt-auth.guard';
import { RolesGuard } from '~/guard/roles.guard';
import { Roles, Role } from '~/decorators/roles.decorator';
import { ResponseData } from '~/global/ResponseData';

@Controller('game-account')
export class GameAccountController {
  constructor(private readonly gameAccountService: GameAccountService) {}

  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @UseInterceptors(
    FileFieldsInterceptor([
      { name: 'mainImage', maxCount: 1 },
      { name: 'additionalImages', maxCount: 10 },
    ]),
  )
  async create(
    @Body() createDto: CreateGameAccountDto,
    @UploadedFiles()
    files: {
      mainImage?: Express.Multer.File[];
      additionalImages?: Express.Multer.File[];
    },
  ) {
    // Validate có ảnh chính không
    if (!files.mainImage || files.mainImage.length === 0) {
      return new ResponseData(
        HttpStatus.BAD_REQUEST,
        'Main image is required',
        null,
      );
    }

    const result = await this.gameAccountService.create(
      createDto,
      files.mainImage[0],
      files.additionalImages,
    );

    return new ResponseData(
      HttpStatus.CREATED,
      'Game account created successfully',
      result,
    );
  }

  @Get()
  async findAll(@Query() filterDto: FilterGameAccountDto) {
    const result = await this.gameAccountService.findAll(filterDto);

    return new ResponseData(
      HttpStatus.OK,
      'Game accounts retrieved successfully',
      result,
    );
  }

  /**
   * GET /game-account/stats-by-type?gameCategoryId=1
   * Public
   */
  @Get('stats-by-type')
  async getStatsByType(@Query('gameCategoryId') gameCategoryId?: number) {
    const stats = await this.gameAccountService.getStatsByType(gameCategoryId);
    return new ResponseData(
      HttpStatus.OK,
      'Account statistics by type retrieved successfully',
      stats,
    );
  }

  /**
   * LẤY 1 GAME ACCOUNT THEO ID
   * GET /game-account/:id
   * Public
   */
  @Get(':id')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const result = await this.gameAccountService.findOne(id);

    return new ResponseData(
      HttpStatus.OK,
      'Game account details retrieved successfully',
      result,
    );
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @UseInterceptors(
    FileFieldsInterceptor([
      { name: 'newMainImage', maxCount: 1 },
      { name: 'newAdditionalImages', maxCount: 10 },
    ]),
  )
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateDto: UpdateGameAccountDto,
    @UploadedFiles()
    files?: {
      newMainImage?: Express.Multer.File[];
      newAdditionalImages?: Express.Multer.File[];
    },
  ) {
    const result = await this.gameAccountService.update(
      id,
      updateDto,
      files?.newMainImage?.[0],
      files?.newAdditionalImages,
    );

    return new ResponseData(
      HttpStatus.OK,
      'Game account updated successfully',
      result,
    );
  }

  /**
   * XÓA GAME ACCOUNT
   * DELETE /game-account/:id
   * Phân quyền: Chỉ ADMIN
   */
  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.gameAccountService.remove(id);

    return new ResponseData(
      HttpStatus.OK,
      'Game account deleted successfully',
      null,
    );
  }
}
