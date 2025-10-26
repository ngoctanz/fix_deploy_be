import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { envConfig } from './env.config';

import * as Entities from '~/entities/index.entity';

export const typeOrmConfig = (
  configService: ConfigService,
): TypeOrmModuleOptions => {
  const config = envConfig(configService);

  const dbConfig: TypeOrmModuleOptions = {
    type: 'postgres',
    host: config.database.host,
    port: config.database.port,
    username: config.database.username,
    password: config.database.password,
    database: config.database.name,
    entities: Object.values(Entities),
    // synchronize: true, // ⚠️ Chỉ dùng trong development, tắt trong production
    ssl:
      config.database.host !== 'localhost'
        ? {
            rejectUnauthorized: false, // Bắt buộc cho Render PostgreSQL
          }
        : false,
    logging: true,
  };
  console.log('📍 Connecting to:', {
    host: dbConfig.host,
    port: dbConfig.port,
    database: dbConfig.database,
    username: dbConfig.username,
    ssl: dbConfig.ssl,
  });

  return dbConfig;
};
