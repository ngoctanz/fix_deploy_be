import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v2 as cloudinary, UploadApiResponse } from 'cloudinary';

@Injectable()
export class CloudinaryService {
  constructor(private readonly config: ConfigService) {
    cloudinary.config({
      cloud_name: this.config.get<string>('CLOUDINARY_NAME'),
      api_key: this.config.get<string>('CLOUDINARY_API_KEY'),
      api_secret: this.config.get<string>('CLOUDINARY_API_SECRET'),
    });
  }

  async uploadImage(
    file: Express.Multer.File,
    folder: string = 'game-accounts',
  ): Promise<{ url: string; publicId: string }> {
    return new Promise((resolve, reject) => {
      // Upload từ buffer (memory storage của Multer)
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: folder,
          resource_type: 'image',
          transformation: [
            { width: 1200, height: 1200, crop: 'limit' },
            { quality: 'auto' },
            { fetch_format: 'auto' },
          ],
        },
        (error, result: UploadApiResponse) => {
          if (error) return reject(error);
          resolve({
            url: result.secure_url,
            publicId: result.public_id,
          });
        },
      );

      // Ghi buffer vào stream
      uploadStream.end(file.buffer);
    });
  }

  async uploadMultipleImages(
    files: Express.Multer.File[],
    folder: string = 'game-accounts',
  ): Promise<{ url: string; publicId: string }[]> {
    // Upload tất cả files song song
    const uploadPromises = files.map((file) => this.uploadImage(file, folder));

    return Promise.all(uploadPromises);
  }

  async deleteImage(publicId: string): Promise<void> {
    try {
      await cloudinary.uploader.destroy(publicId);
    } catch (error) {
      console.error(`Failed to delete image ${publicId}:`, error);
      // Không throw error để không làm gián đoạn flow chính
    }
  }

  async deleteMultipleImages(publicIds: string[]): Promise<void> {
    // Xóa tất cả ảnh song song
    const deletePromises = publicIds.map((publicId) =>
      this.deleteImage(publicId),
    );

    await Promise.all(deletePromises);
  }

  extractPublicId(url: string): string {
    // Cloudinary URL format:
    // https://res.cloudinary.com/{cloud_name}/image/upload/v{version}/{folder}/{subfolder}/{filename}.{ext}
    // hoặc:
    // https://res.cloudinary.com/{cloud_name}/image/upload/{folder}/{subfolder}/{filename}.{ext}

    try {
      // Tìm vị trí của "/upload/" trong URL
      const uploadIndex = url.indexOf('/upload/');
      if (uploadIndex === -1) {
        throw new Error('Invalid Cloudinary URL: missing /upload/');
      }

      // Lấy phần sau "/upload/"
      const afterUpload = url.substring(uploadIndex + '/upload/'.length);

      // Bỏ version nếu có (vXXXXXXXXX/)
      const pathWithoutVersion = afterUpload.replace(/^v\d+\//, '');

      // Tách phần extension (.jpg, .png, etc.)
      const lastDotIndex = pathWithoutVersion.lastIndexOf('.');
      if (lastDotIndex === -1) {
        return pathWithoutVersion; // Không có extension
      }

      // Trả về public_id (path không có extension)
      return pathWithoutVersion.substring(0, lastDotIndex);
    } catch (error) {
      console.error('Error extracting publicId from URL:', url, error);
      // Fallback: dùng cách cũ
      const parts = url.split('/');
      const filename = parts[parts.length - 1];
      const folder = parts[parts.length - 2];
      const filenameWithoutExt = filename.split('.')[0];
      return `${folder}/${filenameWithoutExt}`;
    }
  }
}
