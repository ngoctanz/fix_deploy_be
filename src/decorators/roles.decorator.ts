import { SetMetadata } from '@nestjs/common';
export enum Role {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

/**
 * ROLES DECORATOR
 * Decorator để đánh dấu route cần role gì
 *
 * Cách dùng:
 * @Roles(Role.ADMIN) - Chỉ ADMIN mới truy cập được
 * @Roles(Role.USER, Role.ADMIN) - Cả USER và ADMIN đều truy cập được
 */
export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
