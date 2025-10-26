import { CloudinaryService } from './cloudinary.service';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [],
  providers: [CloudinaryService],
  exports: [CloudinaryService], // Export để các module khác có thể dùng
})
export class CloudinaryModule {}
