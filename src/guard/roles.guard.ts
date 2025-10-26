import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { Role, ROLES_KEY } from '~/decorators/roles.decorator';

/**
 * ROLES GUARD - Guard kiểm tra quyền truy cập dựa trên role
 *
 * CÁCH HOẠT ĐỘNG:
 * 1. Guard này chạy SAU khi JwtAuthGuard đã verify token
 * 2. Lấy danh sách roles yêu cầu từ decorator @Roles()
 * 3. Lấy role của user từ req.user (đã được set bởi JwtStrategy)
 * 4. So sánh role của user với roles yêu cầu
 * 5. Cho phép truy cập nếu khớp, từ chối nếu không khớp
 *
 * LƯU Ý:
 * - Nếu route KHÔNG có @Roles() decorator → Cho phép tất cả (public)
 * - Nếu route có @Roles(Role.ADMIN) → Chỉ ADMIN mới vào được
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Lấy danh sách roles yêu cầu từ decorator @Roles()
    // Ví dụ: @Roles(Role.ADMIN) → requiredRoles = ['ADMIN']
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(), // Method level (ưu tiên)
      context.getClass(), // Class level
    ]);
    if (!requiredRoles) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();

    // Kiểm tra role của user có trong danh sách requiredRoles không
    // user.role được gán từ JwtStrategy.validate()
    return requiredRoles.some((role) => user.role === role);
  }
}
