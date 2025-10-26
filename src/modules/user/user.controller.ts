import {
  Controller,
  Delete,
  Get,
  Put,
  Body,
  Param,
  Query,
  Req,
  UseGuards,
  UsePipes,
  ValidationPipe,
  ParseIntPipe,
} from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '~/guard/jwt-auth.guard';
import { RolesGuard } from '~/guard/roles.guard';
import { Role, Roles } from '~/decorators/roles.decorator';
import { ChangePasswordDto } from '~/dto/change-password.dto';
import { FilterUserDto } from '~/dto/filter-user.dto';
import { ResponseData } from '~/global/ResponseData';
import { UpdateUserDto } from '~/dto/update-user.dto';

/**
 * USER CONTROLLER
 * Quản lý API cho User
 * - User: Xem thông tin, đổi mật khẩu
 * - Admin: Xem tất cả, cập nhật, xóa user
 */
@Controller('user')
@UsePipes(new ValidationPipe({ transform: true }))
export class UserController {
  constructor(private readonly userService: UserService) {}

  /**
   * ADMIN - Lấy tất cả users với phân trang và filter
   */
  @Get('admin/all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async getAllUsers(@Query() filterDto: FilterUserDto) {
    const result = await this.userService.findAll(filterDto);
    return new ResponseData(200, 'Users retrieved successfully', result);
  }

  /**
   * USER - Lấy thông tin của chính mình
   */
  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getMyProfile(@Req() req: any) {
    const userId = req.user.userId;
    const user = await this.userService.findById(userId);
    return new ResponseData(
      200,
      'User information retrieved successfully',
      user,
    );
  }

  /**
   * USER - Tự đổi mật khẩu của mình
   */
  @Put('change-password')
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @Req() req: any,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    const userId = req.user.userId;
    const result = await this.userService.changePassword(
      userId,
      changePasswordDto,
    );
    return new ResponseData(200, result.message, null);
  }

  /**
   * ADMIN - Lấy thông tin user theo ID
   */
  @Get(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async find(@Param('id', ParseIntPipe) id: number) {
    const user = await this.userService.findById(id);
    return new ResponseData(
      200,
      'User information retrieved successfully',
      user,
    );
  }

  /**
   * ADMIN - Xóa user
   */
  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.userService.delete(id);
    return new ResponseData(200, 'User deleted successfully', null);
  }

  // Admin - Update user
  @Put(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    const user = await this.userService.update(id, updateUserDto);
    return new ResponseData(200, 'User updated successfully', user);
  }
}
