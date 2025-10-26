import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Query,
  UseGuards,
  Req,
  ParseIntPipe,
} from '@nestjs/common';
import { OrderService } from './order.service';
import { JwtAuthGuard } from '~/guard/jwt-auth.guard';
import { RolesGuard } from '~/guard/roles.guard';
import { Roles } from '~/decorators/roles.decorator';
import { Role } from '~/enums/role.enum';
import { PurchaseGameAccountDto } from '~/dto/purchase-game-account.dto';
import { FilterOrderDto } from '~/dto/filter-order.dto';
import { ResponseData } from '~/global/ResponseData';
import { HttpStatus } from '~/global/ResponseEnum';
import { OrderResponseDto } from '~/dto/order.response.dto';

@Controller('order')
export class OrderController {
  constructor(private readonly orderService: OrderService) {}
  /**
   * PUBLIC - Lấy các order trong 1 tuần gần nhất cho banner
   * GET /order/recent-banner
   * Trả về: ngày tạo order, tên game, description
   */
  @Get('recent-banner')
  async getRecentOrdersForBanner() {
    try {
      const orders = await this.orderService.getRecentOrdersForBanner();
      return new ResponseData(
        HttpStatus.OK,
        'Recent orders for banner',
        orders,
      );
    } catch (error) {
      return new ResponseData(HttpStatus.ERROR, error.message, null);
    }
  }

  @Post('purchase')
  @UseGuards(JwtAuthGuard)
  async purchaseGameAccount(
    @Req() req,
    @Body() purchaseDto: PurchaseGameAccountDto,
  ) {
    try {
      const userId = req.user.userId;
      const order = await this.orderService.purchaseGameAccount(
        userId,
        purchaseDto,
      );

      // Map sang DTO chỉ trả về các trường cần thiết
      const orderResponse: OrderResponseDto = {
        orderId: order.orderId,
        gameAccountId: order.gameAccountId,
        userId: order.userId,
        gameCategoryName:
          order.gameAccount?.gameCategory?.gameCategoryName ?? '',
        currentPrice: order.gameAccount?.currentPrice ?? '',
      };

      return new ResponseData(
        HttpStatus.OK,
        'Account purchased successfully! Money has been deducted from your account.',
        orderResponse,
      );
    } catch (error) {
      return new ResponseData(HttpStatus.ERROR, error.message, null);
    }
  }

  /**
   * USER - Xem các đơn đã mua của mình
   * GET /order/my-orders?page=1&limit=10&gameAccountId=5
   */
  @Get('my-orders')
  @UseGuards(JwtAuthGuard)
  async getMyOrders(@Req() req, @Query() filterDto: FilterOrderDto) {
    try {
      const userId = req.user.userId;
      const result = await this.orderService.findMyOrders(userId, filterDto);

      return new ResponseData(
        HttpStatus.OK,
        'Your orders retrieved successfully',
        result,
      );
    } catch (error) {
      return new ResponseData(HttpStatus.ERROR, error.message, null);
    }
  }

  /**
   * ADMIN - Xem tất cả đơn đã bán (kèm email người mua)
   * GET /order/admin/all?page=1&limit=10&userId=3&gameAccountId=5
   */
  @Get('admin/all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async getAllOrders(@Query() filterDto: FilterOrderDto) {
    try {
      const result = await this.orderService.findAll(filterDto);

      return new ResponseData(
        HttpStatus.OK,
        'All orders retrieved successfully',
        result,
      );
    } catch (error) {
      return new ResponseData(HttpStatus.ERROR, error.message, null);
    }
  }

  /**
   * Chi tiết 1 order
   * GET /order/:id
   */
  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getOrderDetail(@Param('id', ParseIntPipe) orderId: number) {
    try {
      const order = await this.orderService.findOne(orderId);

      return new ResponseData(
        HttpStatus.OK,
        'Order details retrieved successfully',
        order,
      );
    } catch (error) {
      return new ResponseData(HttpStatus.ERROR, error.message, null);
    }
  }
  // admin xem danh sách đơn hàng của user
  @Get('admin/user/:userId')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async getOrdersByUserId(@Param('userId') userId: number) {
    const result = await this.orderService.findAllByUserId(userId);
    return new ResponseData(
      200,
      "User's orders retrieved successfully",
      result,
    );
  }
}
