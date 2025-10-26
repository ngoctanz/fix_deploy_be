import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { OrderEntity } from '~/entities/order.entity';
import { UserEntity } from '~/entities/user.entity';
import { GameAccountEntity } from '~/entities/game-account.entity';
import { PurchaseGameAccountDto } from '~/dto/purchase-game-account.dto';
import { FilterOrderDto } from '~/dto/filter-order.dto';

/**
 * ORDER SERVICE
 * Xử lý logic nghiệp vụ cho Order (mua account)
 */
@Injectable()
export class OrderService {
  constructor(
    @InjectRepository(OrderEntity)
    private readonly orderRepository: Repository<OrderEntity>,

    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,

    @InjectRepository(GameAccountEntity)
    private readonly gameAccountRepository: Repository<GameAccountEntity>,

    private readonly dataSource: DataSource, // Để sử dụng transaction
  ) {}

  async purchaseGameAccount(
    userId: number,
    purchaseDto: PurchaseGameAccountDto,
  ): Promise<OrderEntity> {
    return await this.dataSource.transaction(async (manager) => {
      const user = await manager.findOne(UserEntity, {
        where: { userId },
      });
      if (!user) {
        throw new NotFoundException('User not found');
      }
      const gameAccount = await manager.findOne(GameAccountEntity, {
        where: { gameAccountId: purchaseDto.gameAccountId },
        lock: { mode: 'pessimistic_write' }, // Lock để tránh race condition
      });
      if (!gameAccount) {
        throw new NotFoundException(
          `Game account with ID ${purchaseDto.gameAccountId} not found`,
        );
      }

      if (gameAccount.status !== 'available') {
        throw new BadRequestException(
          `This account has been sold or is reserved. Status: ${gameAccount.status}`,
        );
      }

      // 4. Kiểm tra số tiền
      const accountPrice = Number(gameAccount.currentPrice);
      const userMoney = Number(user.money);
      if (userMoney < accountPrice) {
        throw new BadRequestException(
          `Insufficient balance. Need ${accountPrice.toLocaleString('en-US')} VND, current balance ${userMoney.toLocaleString('en-US')} VND`,
        );
      }

      // 5. Trừ tiền user
      user.money = userMoney - accountPrice;
      await manager.save(UserEntity, user);

      // 6. Update trạng thái account thành sold
      gameAccount.status = 'sold';
      await manager.save(GameAccountEntity, gameAccount);

      // 7. Tạo order
      const order = manager.create(OrderEntity, {
        userId,
        gameAccountId: purchaseDto.gameAccountId,
      });
      const savedOrder = await manager.save(OrderEntity, order);

      const orderWithRelations = await manager.findOne(OrderEntity, {
        where: { orderId: savedOrder.orderId },
        relations: ['user', 'gameAccount', 'gameAccount.gameCategory'],
      });

      return orderWithRelations!;
    });
  }

  /**
   * USER - Xem tất cả đơn đã mua của mình
   */
  async findMyOrders(
    userId: number,
    filterDto: FilterOrderDto,
  ): Promise<{
    data: OrderEntity[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const { page = 1, limit = 10, gameAccountId } = filterDto;

    const queryBuilder = this.orderRepository
      .createQueryBuilder('order')
      .leftJoinAndSelect('order.gameAccount', 'gameAccount')
      .leftJoinAndSelect('gameAccount.gameCategory', 'gameCategory')
      .where('order.userId = :userId', { userId });

    // Filter theo gameAccountId nếu có
    if (gameAccountId) {
      queryBuilder.andWhere('order.gameAccountId = :gameAccountId', {
        gameAccountId,
      });
    }
    queryBuilder.orderBy('order.createdAt', 'DESC');

    const total = await queryBuilder.getCount();
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
   * PUBLIC - Lấy các order trong 1 tuần gần nhất cho banner
   * Trả về: ngày tạo order, tên game, description
   */
  async getRecentOrdersForBanner(): Promise<
    Array<{
      createdAt: Date;
      gameName: string;
      description: string;
      email: string;
    }>
  > {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    const orders = await this.orderRepository
      .createQueryBuilder('order')
      .leftJoinAndSelect('order.gameAccount', 'gameAccount')
      .leftJoinAndSelect('gameAccount.gameCategory', 'gameCategory')
      .leftJoinAndSelect('order.user', 'user')
      .where('order.createdAt >= :oneWeekAgo', { oneWeekAgo })
      .orderBy('order.createdAt', 'DESC')
      .getMany();

    return orders.map((order: any) => {
      const email = order.user?.email ?? '';
      const maskedEmail = email.replace(
        /^(.{2})(.*)(.{2})@(.*)$/,
        (_, a, _mid, b, domain) => `${a}*****${b}@${domain}`,
      );

      return {
        createdAt: order.createdAt,
        gameName: order.gameAccount?.gameCategory?.gameCategoryName || '',
        description: order.gameAccount?.description || '',
        email: maskedEmail || email,
      };
    });
  }

  /**
   * ADMIN - Xem tất cả đơn đã bán (kèm email người mua)
   */
  async findAll(filterDto: FilterOrderDto): Promise<{
    data: OrderEntity[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const { page = 1, limit = 10, userId, gameAccountId } = filterDto;

    const queryBuilder = this.orderRepository
      .createQueryBuilder('order')
      .leftJoinAndSelect('order.user', 'user')
      .leftJoinAndSelect('order.gameAccount', 'gameAccount')
      .leftJoinAndSelect('gameAccount.gameCategory', 'gameCategory')
      .select([
        'order.orderId',
        'order.userId',
        'order.gameAccountId',
        'order.createdAt',
        'user.userId',
        'user.email',
        'user.money',
        'gameAccount.gameAccountId',
        'gameAccount.currentPrice',
        'gameAccount.status',
        'gameAccount.typeAccount',
        'gameCategory.gameCategoryId',
        'gameCategory.gameCategoryName',
      ]);

    // Filter theo userId nếu có
    if (userId) {
      queryBuilder.andWhere('order.userId = :userId', { userId });
    }

    // Filter theo gameAccountId nếu có
    if (gameAccountId) {
      queryBuilder.andWhere('order.gameAccountId = :gameAccountId', {
        gameAccountId,
      });
    }

    // Sắp xếp theo createdAt DESC (mới nhất trước)
    queryBuilder.orderBy('order.createdAt', 'DESC');

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
   * Lấy chi tiết 1 order
   */
  async findOne(orderId: number): Promise<OrderEntity> {
    const order = await this.orderRepository.findOne({
      where: { orderId },
      relations: ['user', 'gameAccount', 'gameAccount.gameCategory'],
    });

    if (!order) {
      throw new NotFoundException(`Order with ID ${orderId} not found`);
    }

    return order;
  }
  // admin xem danh sách đơn hàng của user
  async findAllByUserId(userId: number): Promise<OrderEntity[]> {
    return this.orderRepository.find({
      where: { userId },
    });
  }
}
