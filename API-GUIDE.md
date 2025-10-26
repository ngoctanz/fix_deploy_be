# 🎮 API DOCUMENTATION - GAME ACCOUNT SHOP

## 📋 MỤC LỤC

- [Thông tin chung](#thông-tin-chung)
- [Authentication APIs](#authentication-apis)
- [User APIs](#user-apis)
- [Game Category APIs](#game-category-apis)
- [Game Account APIs](#game-account-apis)
- [Order APIs](#order-apis)
- [Request Deposit APIs](#request-deposit-apis)
- [Response Format](#response-format)

---

## 🌐 THÔNG TIN CHUNG

### Base URL

```
Development: http://localhost:3001
Production: https://your-domain.com
```

### Authentication

Hệ thống sử dụng **JWT Token** được lưu trong **HTTP-Only Cookies**:

- `accessToken`: Hết hạn sau 30 phút
- `refreshToken`: Hết hạn sau 7 ngày

### Roles

- `USER`: Người dùng thông thường
- `ADMIN`: Quản trị viên

---

## 🔐 AUTHENTICATION APIs

### 1. Đăng ký tài khoản

**POST** `/auth/register`

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "123456"
}
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Đăng ký thành công! Vui lòng đăng nhập.",
  "data": null
}
```

**Cookies được set:**

- `accessToken` (HTTP-Only)
- `refreshToken` (HTTP-Only)

---

### 2. Đăng nhập

**POST** `/auth/login`

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "123456"
}
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Đăng nhập thành công",
  "data": null
}
```

**Cookies được set:**

- `accessToken` (HTTP-Only, 30 phút)
- `refreshToken` (HTTP-Only, 7 ngày)

---

### 3. Lấy thông tin profile

**GET** `/auth/profile`

**Headers:**

```
Cookie: accessToken=<jwt-token>
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy thông tin profile thành công",
  "data": {
    "userId": 1,
    "email": "user@example.com",
    "money": 500000,
    "role": "USER"
  }
}
```

---

### 4. Refresh Access Token

**POST** `/auth/refresh`

**Headers:**

```
Cookie: refreshToken=<jwt-token>
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Làm mới token thành công",
  "data": null
}
```

**Cookies được cập nhật:**

- `accessToken` (HTTP-Only, 30 phút mới)

---

### 5. Đăng xuất

**POST** `/auth/logout`

**Headers:**

```
Cookie: accessToken=<jwt-token>
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Đăng xuất thành công",
  "data": null
}
```

**Cookies bị xóa:**

- `accessToken`
- `refreshToken`

---

## 👤 USER APIs

### 1. Lấy thông tin user của mình

**GET** `/user/me`

**Role:** USER (đã đăng nhập)

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy thông tin user thành công",
  "data": {
    "userId": 1,
    "email": "user@example.com",
    "money": 500000,
    "role": "USER",
    "createdAt": "2025-01-15T10:00:00.000Z",
    "updatedAt": "2025-01-15T10:00:00.000Z"
  }
}
```

---

### 2. Đổi mật khẩu

**PUT** `/user/change-password`

**Role:** USER

**Request Body:**

```json
{
  "oldPassword": "123456",
  "newPassword": "newpass123"
}
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Đổi mật khẩu thành công",
  "data": null
}
```

---

### 3. [ADMIN] Lấy danh sách tất cả users

**GET** `/user/admin/all?page=1&limit=10&role=USER&search=example`

**Role:** ADMIN

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | number | No | 1 | Trang hiện tại |
| limit | number | No | 10 | Số lượng mỗi trang |
| role | string | No | - | Lọc theo role (USER/ADMIN) |
| search | string | No | - | Tìm kiếm theo email |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy danh sách users thành công",
  "data": {
    "users": [
      {
        "userId": 1,
        "email": "user@example.com",
        "money": 500000,
        "role": "USER",
        "createdAt": "2025-01-15T10:00:00.000Z"
      }
    ],
    "total": 50,
    "page": 1,
    "limit": 10,
    "totalPages": 5
  }
}
```

---

### 4. [ADMIN] Lấy thông tin user theo ID

**GET** `/user/:id`

**Role:** ADMIN

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy thông tin user thành công",
  "data": {
    "userId": 1,
    "email": "user@example.com",
    "money": 500000,
    "role": "USER",
    "createdAt": "2025-01-15T10:00:00.000Z"
  }
}
```

---

### 5. [ADMIN] Xóa user

**DELETE** `/user/:id`

**Role:** ADMIN

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Xóa user thành công",
  "data": null
}
```

---

## 📂 GAME CATEGORY APIs

### 1. Lấy danh sách tất cả categories

**GET** `/game-category`

**Public** - Không cần đăng nhập

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy danh sách categories thành công",
  "data": [
    {
      "gameCategoryId": 1,
      "gameCategoryName": "Liên Quân Mobile",
      "imageGameCategory": "https://cloudinary.com/image1.jpg",
      "createdAt": "2025-01-15T10:00:00.000Z",
      "updatedAt": "2025-01-15T10:00:00.000Z"
    },
    {
      "gameCategoryId": 2,
      "gameCategoryName": "PUBG Mobile",
      "imageGameCategory": "https://cloudinary.com/image2.jpg",
      "createdAt": "2025-01-15T10:00:00.000Z",
      "updatedAt": "2025-01-15T10:00:00.000Z"
    }
  ]
}
```

---

### 2. Lấy chi tiết 1 category

**GET** `/game-category/:id`

**Public** - Không cần đăng nhập

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy chi tiết category thành công",
  "data": {
    "gameCategoryId": 1,
    "gameCategoryName": "Liên Quân Mobile",
    "imageGameCategory": "https://cloudinary.com/image1.jpg",
    "createdAt": "2025-01-15T10:00:00.000Z",
    "updatedAt": "2025-01-15T10:00:00.000Z"
  }
}
```

---

### 3. [ADMIN] Tạo category mới

**POST** `/game-category`

**Role:** ADMIN

**Content-Type:** `multipart/form-data`

**Form Data:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| gameCategoryName | string | Yes | Tên danh mục game |
| image | file | Yes | Ảnh đại diện (jpg/png) |

**Example Request (FormData):**

```javascript
const formData = new FormData();
formData.append('gameCategoryName', 'Liên Quân Mobile');
formData.append('image', fileInput.files[0]);
```

**Response Success (201):**

```json
{
  "statusCode": 201,
  "message": "Tạo category thành công",
  "data": {
    "gameCategoryId": 1,
    "gameCategoryName": "Liên Quân Mobile",
    "imageGameCategory": "https://cloudinary.com/image1.jpg",
    "createdAt": "2025-01-15T10:00:00.000Z"
  }
}
```

---

### 4. [ADMIN] Cập nhật category

**PUT** `/game-category/:id`

**Role:** ADMIN

**Content-Type:** `multipart/form-data`

**Form Data:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| gameCategoryName | string | No | Tên danh mục mới |
| newImage | file | No | Ảnh mới (nếu muốn thay đổi) |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Cập nhật category thành công",
  "data": {
    "gameCategoryId": 1,
    "gameCategoryName": "Liên Quân Mobile Updated",
    "imageGameCategory": "https://cloudinary.com/new-image.jpg",
    "updatedAt": "2025-01-15T12:00:00.000Z"
  }
}
```

---

### 5. [ADMIN] Xóa category

**DELETE** `/game-category/:id`

**Role:** ADMIN

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Xóa category thành công",
  "data": null
}
```

---

## 🎮 GAME ACCOUNT APIs

### 1. Lấy danh sách game accounts (có filter + phân trang)

**GET** `/game-account?page=1&limit=10&gameCategoryId=1&status=available&typeAccount=VIP&minPrice=100000&maxPrice=500000&search=vip&sortBy=currentPrice&sortOrder=ASC`

**Public** - Không cần đăng nhập

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | number | No | 1 | Trang hiện tại |
| limit | number | No | 10 | Số lượng mỗi trang |
| gameCategoryId | number | No | - | Lọc theo danh mục game |
| status | string | No | - | Lọc theo trạng thái (available/sold/reserved) |
| typeAccount | string | No | - | Lọc theo loại (VIP/Normal) |
| minPrice | number | No | - | Giá tối thiểu |
| maxPrice | number | No | - | Giá tối đa |
| search | string | No | - | Tìm kiếm trong description |
| sortBy | string | No | createdAt | Sắp xếp theo (createdAt/currentPrice/originalPrice) |
| sortOrder | string | No | DESC | Thứ tự (ASC/DESC) |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy danh sách game account thành công",
  "data": {
    "gameAccounts": [
      {
        "gameAccountId": 1,
        "status": "available",
        "gameCategoryId": 1,
        "originalPrice": "500000.00",
        "currentPrice": "350000.00",
        "description": "Tài khoản VIP, rank Kim Cương, 50 tướng, 100 skin",
        "mainImageUrl": "https://cloudinary.com/main-image.jpg",
        "typeAccount": "VIP",
        "createdAt": "2025-01-15T10:00:00.000Z",
        "updatedAt": "2025-01-15T10:00:00.000Z",
        "gameCategory": {
          "gameCategoryId": 1,
          "gameCategoryName": "Liên Quân Mobile",
          "imageGameCategory": "https://cloudinary.com/category.jpg"
        },
        "images": [
          {
            "imageId": 1,
            "imageUrl": "https://cloudinary.com/image1.jpg",
            "publicId": "game_accounts/xyz123"
          },
          {
            "imageId": 2,
            "imageUrl": "https://cloudinary.com/image2.jpg",
            "publicId": "game_accounts/abc456"
          }
        ]
      }
    ],
    "total": 25,
    "page": 1,
    "limit": 10,
    "totalPages": 3
  }
}
```

---

### 2. Lấy chi tiết 1 game account

**GET** `/game-account/:id`

**Public** - Không cần đăng nhập

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy chi tiết game account thành công",
  "data": {
    "gameAccountId": 1,
    "status": "available",
    "gameCategoryId": 1,
    "originalPrice": "500000.00",
    "currentPrice": "350000.00",
    "description": "Tài khoản VIP, rank Kim Cương",
    "mainImageUrl": "https://cloudinary.com/main.jpg",
    "typeAccount": "VIP",
    "createdAt": "2025-01-15T10:00:00.000Z",
    "gameCategory": {
      "gameCategoryId": 1,
      "gameCategoryName": "Liên Quân Mobile"
    },
    "images": [
      {
        "imageId": 1,
        "imageUrl": "https://cloudinary.com/image1.jpg"
      }
    ]
  }
}
```

---

### 3. [ADMIN] Tạo game account mới

**POST** `/game-account`

**Role:** ADMIN

**Content-Type:** `multipart/form-data`

**Form Data:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| gameCategoryId | number | Yes | ID danh mục game |
| originalPrice | number | Yes | Giá gốc |
| currentPrice | number | Yes | Giá hiện tại |
| description | string | No | Mô tả chi tiết |
| status | string | No | available/sold/reserved (default: available) |
| typeAccount | string | No | VIP/Normal (default: Normal) |
| mainImage | file | Yes | Ảnh đại diện chính |
| additionalImages[] | file[] | No | Tối đa 10 ảnh phụ |

**Example Request (JavaScript):**

```javascript
const formData = new FormData();
formData.append('gameCategoryId', '1');
formData.append('originalPrice', '500000');
formData.append('currentPrice', '350000');
formData.append('description', 'Tài khoản VIP, rank Kim Cương');
formData.append('status', 'available');
formData.append('typeAccount', 'VIP');
formData.append('mainImage', mainImageFile);
formData.append('additionalImages', additionalFile1);
formData.append('additionalImages', additionalFile2);
```

**Response Success (201):**

```json
{
  "statusCode": 201,
  "message": "Tạo game account thành công",
  "data": {
    "gameAccountId": 1,
    "status": "available",
    "gameCategoryId": 1,
    "originalPrice": "500000.00",
    "currentPrice": "350000.00",
    "description": "Tài khoản VIP, rank Kim Cương",
    "mainImageUrl": "https://cloudinary.com/main.jpg",
    "typeAccount": "VIP",
    "images": [
      {
        "imageId": 1,
        "imageUrl": "https://cloudinary.com/image1.jpg"
      }
    ]
  }
}
```

---

### 4. [ADMIN] Cập nhật game account

**PUT** `/game-account/:id`

**Role:** ADMIN

**Content-Type:** `multipart/form-data`

**Form Data:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| gameCategoryId | number | No | ID danh mục game mới |
| originalPrice | number | No | Giá gốc mới |
| currentPrice | number | No | Giá hiện tại mới |
| description | string | No | Mô tả mới |
| status | string | No | available/sold/reserved |
| typeAccount | string | No | VIP/Normal |
| newMainImage | file | No | Ảnh chính mới (thay thế ảnh cũ) |
| newAdditionalImages[] | file[] | No | Ảnh phụ mới |
| deleteImageIds[] | number[] | No | Danh sách ID ảnh cần xóa |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Cập nhật game account thành công",
  "data": {
    "gameAccountId": 1,
    "status": "sold",
    "currentPrice": "300000.00",
    "updatedAt": "2025-01-15T12:00:00.000Z"
  }
}
```

---

### 5. [ADMIN] Xóa game account

**DELETE** `/game-account/:id`

**Role:** ADMIN

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Xóa game account thành công",
  "data": null
}
```

---

## 🛒 ORDER APIs

### 1. [USER] Mua game account

**POST** `/order/purchase`

**Role:** USER

**Request Body:**

```json
{
  "gameAccountId": 1
}
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Mua account thành công! Tiền đã được trừ khỏi tài khoản.",
  "data": {
    "orderId": 1,
    "userId": 2,
    "gameAccountId": 1,
    "price": "350000.00",
    "createdAt": "2025-01-15T14:00:00.000Z"
  }
}
```

**Response Error (400):**

```json
{
  "statusCode": 400,
  "message": "Số dư không đủ để mua tài khoản này",
  "data": null
}
```

---

### 2. [USER] Xem đơn hàng của mình

**GET** `/order/my-orders?page=1&limit=10&gameAccountId=1`

**Role:** USER

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | number | No | 1 | Trang hiện tại |
| limit | number | No | 10 | Số lượng mỗi trang |
| gameAccountId | number | No | - | Lọc theo game account |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy danh sách đơn hàng của bạn thành công",
  "data": {
    "orders": [
      {
        "orderId": 1,
        "userId": 2,
        "gameAccountId": 1,
        "price": "350000.00",
        "createdAt": "2025-01-15T14:00:00.000Z",
        "gameAccount": {
          "gameAccountId": 1,
          "description": "Tài khoản VIP",
          "mainImageUrl": "https://cloudinary.com/main.jpg",
          "gameCategory": {
            "gameCategoryName": "Liên Quân Mobile"
          }
        }
      }
    ],
    "total": 5,
    "page": 1,
    "limit": 10,
    "totalPages": 1
  }
}
```

---

### 3. [ADMIN] Xem tất cả đơn hàng

**GET** `/order/admin/all?page=1&limit=10&userId=2&gameAccountId=1`

**Role:** ADMIN

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | number | No | 1 | Trang hiện tại |
| limit | number | No | 10 | Số lượng mỗi trang |
| userId | number | No | - | Lọc theo user |
| gameAccountId | number | No | - | Lọc theo game account |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy danh sách tất cả đơn hàng thành công",
  "data": {
    "orders": [
      {
        "orderId": 1,
        "userId": 2,
        "gameAccountId": 1,
        "price": "350000.00",
        "createdAt": "2025-01-15T14:00:00.000Z",
        "user": {
          "userId": 2,
          "email": "buyer@example.com"
        },
        "gameAccount": {
          "gameAccountId": 1,
          "description": "Tài khoản VIP",
          "mainImageUrl": "https://cloudinary.com/main.jpg"
        }
      }
    ],
    "total": 50,
    "page": 1,
    "limit": 10,
    "totalPages": 5
  }
}
```

---

### 4. Xem chi tiết 1 đơn hàng

**GET** `/order/:id`

**Role:** USER (chỉ xem được đơn của mình) hoặc ADMIN (xem tất cả)

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy chi tiết đơn hàng thành công",
  "data": {
    "orderId": 1,
    "userId": 2,
    "gameAccountId": 1,
    "price": "350000.00",
    "createdAt": "2025-01-15T14:00:00.000Z",
    "user": {
      "email": "buyer@example.com"
    },
    "gameAccount": {
      "description": "Tài khoản VIP",
      "mainImageUrl": "https://cloudinary.com/main.jpg",
      "gameCategory": {
        "gameCategoryName": "Liên Quân Mobile"
      }
    }
  }
}
```

---

## 💰 REQUEST DEPOSIT APIs

### 1. [USER] Tạo yêu cầu nạp tiền

**POST** `/request-deposit`

**Role:** USER

**Content-Type:** `multipart/form-data`

**Form Data:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| description | string | Yes | Mô tả yêu cầu (số tiền, ngân hàng, ...) |
| billImage | file | Yes | Ảnh bill chuyển khoản |

**Example Request:**

```javascript
const formData = new FormData();
formData.append('description', 'Chuyển khoản 500.000 VND qua Vietcombank');
formData.append('billImage', billImageFile);
```

**Response Success (201):**

```json
{
  "statusCode": 201,
  "message": "Tạo yêu cầu nạp tiền thành công. Vui lòng đợi admin duyệt.",
  "data": {
    "requestDepositId": 1,
    "userId": 2,
    "description": "Chuyển khoản 500.000 VND qua Vietcombank",
    "imgUrl": "https://cloudinary.com/bill.jpg",
    "status": "pending",
    "createdAt": "2025-01-15T15:00:00.000Z"
  }
}
```

---

### 2. [USER] Xem yêu cầu nạp tiền của mình

**GET** `/request-deposit/my-requests?page=1&limit=10&status=pending`

**Role:** USER

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | number | No | 1 | Trang hiện tại |
| limit | number | No | 10 | Số lượng mỗi trang |
| status | string | No | - | Lọc theo trạng thái (pending/approved/rejected) |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy danh sách yêu cầu của bạn thành công",
  "data": {
    "requests": [
      {
        "requestDepositId": 1,
        "userId": 2,
        "description": "Chuyển khoản 500.000 VND",
        "imgUrl": "https://cloudinary.com/bill.jpg",
        "status": "pending",
        "createdAt": "2025-01-15T15:00:00.000Z"
      }
    ],
    "total": 3,
    "page": 1,
    "limit": 10,
    "totalPages": 1
  }
}
```

---

### 3. [ADMIN] Xem tất cả yêu cầu nạp tiền

**GET** `/request-deposit/admin/all?page=1&limit=10&status=pending&userId=2`

**Role:** ADMIN

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | number | No | 1 | Trang hiện tại |
| limit | number | No | 10 | Số lượng mỗi trang |
| status | string | No | - | Lọc theo trạng thái |
| userId | number | No | - | Lọc theo user |

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy danh sách yêu cầu thành công",
  "data": {
    "requests": [
      {
        "requestDepositId": 1,
        "userId": 2,
        "description": "Chuyển khoản 500.000 VND",
        "imgUrl": "https://cloudinary.com/bill.jpg",
        "status": "pending",
        "createdAt": "2025-01-15T15:00:00.000Z",
        "user": {
          "email": "user@example.com"
        }
      }
    ],
    "total": 15,
    "page": 1,
    "limit": 10,
    "totalPages": 2
  }
}
```

---

### 4. [ADMIN] Xem chi tiết yêu cầu

**GET** `/request-deposit/:id`

**Role:** ADMIN

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Lấy chi tiết yêu cầu thành công",
  "data": {
    "requestDepositId": 1,
    "userId": 2,
    "description": "Chuyển khoản 500.000 VND qua Vietcombank",
    "imgUrl": "https://cloudinary.com/bill.jpg",
    "status": "pending",
    "createdAt": "2025-01-15T15:00:00.000Z",
    "user": {
      "email": "user@example.com",
      "money": 100000
    }
  }
}
```

---

### 5. [ADMIN] Cập nhật trạng thái yêu cầu

**PUT** `/request-deposit/:id/status`

**Role:** ADMIN

**Request Body:**

```json
{
  "status": "approved"
}
```

**Giá trị status:**

- `approved`: Duyệt yêu cầu
- `rejected`: Từ chối yêu cầu

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Cập nhật trạng thái thành approved thành công",
  "data": {
    "requestDepositId": 1,
    "status": "approved",
    "updatedAt": "2025-01-15T16:00:00.000Z"
  }
}
```

---

### 6. [ADMIN] Cộng tiền cho user

**POST** `/request-deposit/admin/add-money`

**Role:** ADMIN

**Request Body:**

```json
{
  "userId": 2,
  "amount": 500000
}
```

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Cộng 500,000 VND vào tài khoản user 2 thành công",
  "data": {
    "userId": 2,
    "email": "user@example.com",
    "money": 600000
  }
}
```

---

### 7. [ADMIN] Xóa yêu cầu nạp tiền

**DELETE** `/request-deposit/:id`

**Role:** ADMIN

**Response Success (200):**

```json
{
  "statusCode": 200,
  "message": "Xóa yêu cầu nạp tiền thành công",
  "data": null
}
```

---

## 📦 RESPONSE FORMAT

### Success Response

```json
{
  "statusCode": 200,
  "message": "Thông điệp thành công",
  "data": {
    /* Dữ liệu trả về */
  }
}
```

### Error Response

```json
{
  "statusCode": 400,
  "message": "Thông báo lỗi",
  "data": null
}
```

### Common HTTP Status Codes

| Code | Meaning                             |
| ---- | ----------------------------------- |
| 200  | OK - Thành công                     |
| 201  | Created - Tạo mới thành công        |
| 400  | Bad Request - Dữ liệu không hợp lệ  |
| 401  | Unauthorized - Chưa đăng nhập       |
| 403  | Forbidden - Không có quyền truy cập |
| 404  | Not Found - Không tìm thấy          |
| 500  | Internal Server Error - Lỗi server  |

---

## 🔒 COOKIE & CORS CONFIG

### Cookies được sử dụng

- **accessToken**: JWT token cho xác thực (30 phút)
- **refreshToken**: JWT token để làm mới (7 ngày)

### Cookie Attributes

- `httpOnly`: true (Không thể truy cập bằng JavaScript)
- `secure`: true khi dùng HTTPS
- `sameSite`: 'none' (Cho phép cross-domain)

### CORS

- `origin`: Frontend domain (cấu hình trong `.env`)
- `credentials`: true (Cho phép gửi cookies)

---

## 🚀 QUICK START

### 1. Test Authentication

```bash
# Đăng ký
POST http://localhost:3001/auth/register
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "123456"
}

# Đăng nhập
POST http://localhost:3001/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "123456"
}

# Lấy profile (cookies tự động gửi)
GET http://localhost:3001/auth/profile
```

### 2. Test Upload Files (Postman/Thunder Client)

```
POST http://localhost:3001/game-category
Headers:
  Cookie: accessToken=<your-jwt-token>

Body (form-data):
  gameCategoryName: Liên Quân Mobile
  image: [chọn file]
```

---

## 📝 NOTES

1. **Authentication**: Tất cả API có `@UseGuards(JwtAuthGuard)` cần gửi cookie `accessToken`
2. **File Upload**: Sử dụng `multipart/form-data` cho các API upload ảnh
3. **Pagination**: Mặc định `page=1`, `limit=10`
4. **Cloudinary**: Tất cả ảnh được upload lên Cloudinary và trả về URL
5. **Soft Delete**: Một số entity có thể dùng soft delete (chưa implement)

---

**Developed with ❤️ by hieuvolaptrinh**

Last updated: January 2025
