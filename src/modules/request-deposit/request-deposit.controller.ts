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
  Req,
  UseInterceptors,
  UploadedFile,
  ParseIntPipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { RequestDepositService } from './request-deposit.service';
import { JwtAuthGuard } from '~/guard/jwt-auth.guard';
import { RolesGuard } from '~/guard/roles.guard';
import { Role, Roles } from '~/decorators/roles.decorator';
import { CreateRequestDepositDto } from '~/dto/create-request-deposit.dto';
import { FilterRequestDepositDto } from '~/dto/filter-request-deposit.dto';
import { UpdateRequestDepositDto } from '~/dto/update-request-deposit.dto';
import { AddMoneyToUserDto } from '~/dto/add-money-to-user.dto';
import { ResponseData } from '~/global/ResponseData';

@Controller('request-deposit')
export class RequestDepositController {
  constructor(private readonly requestDepositService: RequestDepositService) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(FileInterceptor('billImage'))
  async create(
    @Req() req: any,
    @Body() createDto: CreateRequestDepositDto,
    @UploadedFile() billImage: Express.Multer.File,
  ) {
    if (!billImage) {
      return new ResponseData(400, 'Please upload bill transfer image', null);
    }

    const userId = req.user.userId; // Lấy từ JWT token
    const data = await this.requestDepositService.create(
      userId,
      createDto,
      billImage,
    );

    return new ResponseData(
      201,
      'Deposit request created successfully. Please wait for admin approval.',
      data,
    );
  }

  /**
   * ADMIN - Lấy tất cả yêu cầu nạp tiền (có phân trang, lọc)
   * Kèm theo email của user
   * Mặc định: pending lên đầu
   */
  @Get('admin/all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async findAll(@Query() filterDto: FilterRequestDepositDto) {
    const result = await this.requestDepositService.findAll(filterDto);
    return new ResponseData(
      200,
      'Deposit requests retrieved successfully',
      result,
    );
  }

  /**
   * USER - Lấy tất cả yêu cầu của chính mình
   * Có phân trang và lọc theo status
   */
  @Get('my-requests')
  @UseGuards(JwtAuthGuard)
  async findMyRequests(
    @Req() req: any,
    @Query() filterDto: FilterRequestDepositDto,
  ) {
    const userId = req.user.userId;
    const result = await this.requestDepositService.findMyRequests(
      userId,
      filterDto,
    );

    return new ResponseData(
      200,
      'Your deposit requests retrieved successfully',
      result,
    );
  }

  /**
   * ADMIN - Lấy chi tiết 1 yêu cầu theo ID
   */
  @Get(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const data = await this.requestDepositService.findOne(id);
    return new ResponseData(
      200,
      'Deposit request details retrieved successfully',
      data,
    );
  }

  /**
   * ADMIN - Cập nhật trạng thái yêu cầu (approve/reject)
   */
  @Put(':id/status')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async updateStatus(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateDto: UpdateRequestDepositDto,
  ) {
    const data = await this.requestDepositService.updateStatus(id, updateDto);
    return new ResponseData(
      200,
      `Status updated to ${updateDto.status} successfully`,
      data,
    );
  }

  /**
   * ADMIN - Cộng tiền vào tài khoản user
   */
  @Post('admin/add-money')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async addMoneyToUser(@Body() addMoneyDto: AddMoneyToUserDto) {
    const data = await this.requestDepositService.addMoneyToUser(addMoneyDto);
    return new ResponseData(
      200,
      `Added ${addMoneyDto.amount.toLocaleString('en-US')} VND to user ${addMoneyDto.userId} successfully`,
      data,
    );
  }

  /**
   * ADMIN - Xóa yêu cầu nạp tiền
   * Xóa cả ảnh trên Cloudinary
   */
  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.requestDepositService.remove(id);
    return new ResponseData(200, 'Deposit request deleted successfully', null);
  }

  // Tạo api để lấy danh sách yêu cầu nạp tiền của user
  @Get('admin/user/:userId')
  @UseGuards(JwtAuthGuard)
  async findAllByAdmin(@Param('userId') userId: number, @Req() req) {
    // (Tuỳ bạn có muốn kiểm tra role admin hay không)
    const admin = req.user;
    if (admin.role !== 'ADMIN') {
      return new ResponseData(403, 'You do not have access permission', null);
    }

    const result = await this.requestDepositService.findAllByUserId(userId);

    return new ResponseData(
      200,
      `Deposit requests for user ${userId} retrieved successfully`,
      result,
    );
  }
}
