# TLS-Crypto

此包实现了TLS协议所需的加密算法和功能，包括：

## 功能特性

- 对称加密算法：AES-GCM、AES-CBC、ChaCha20-Poly1305、3DES等
- 非对称加密算法：RSA、ECDSA、EdDSA、DSA等
- 密钥交换算法：ECDHE、DHE、RSA等
- 哈希函数：SHA-256、SHA-384、SHA-512、MD5等
- 消息认证码：HMAC、AEAD、GMAC等
- 随机数生成器：CSPRNG
- 密钥导出函数：HKDF
- 曲线实现：P-256、P-384、X25519、X448等

## 使用要求

- PHP 8.1+
- ext-ctype
- psr/log

## 安装

```bash
composer require tourze/tls-crypto
```

## 基本用法

### 随机数生成

```php
use Tourze\TLSCrypto\CryptoFactory;

// 创建随机数生成器
$random = CryptoFactory::createRandom();

// 生成16字节的随机数
$randomBytes = $random->getRandomBytes(16);

// 生成1-100范围内的随机整数
$randomInt = $random->getRandomInt(1, 100);
```

### 哈希函数

```php
use Tourze\TLSCrypto\CryptoFactory;

// 创建SHA-256哈希函数
$hash = CryptoFactory::createHash('sha256');

// 计算哈希值
$data = 'Hello, World!';
$hashValue = $hash->hash($data);

// 使用增量哈希
$context = $hash->createContext();
$hash->updateContext($context, 'Hello, ');
$hash->updateContext($context, 'World!');
$hashValue = $hash->finalizeContext($context);
```

### HMAC消息认证码

```php
use Tourze\TLSCrypto\CryptoFactory;

// 创建基于SHA-256的HMAC
$hmac = CryptoFactory::createMac('hmac-sha256');

// 计算HMAC
$data = 'Message to authenticate';
$key = $random->getRandomBytes(32);
$mac = $hmac->compute($data, $key);

// 验证HMAC
$isValid = $hmac->verify($data, $mac, $key);
```

### AES-GCM加密

```php
use Tourze\TLSCrypto\CryptoFactory;

// 创建AES-256-GCM加密算法
$cipher = CryptoFactory::createCipher('aes-256-gcm');

// 生成随机密钥和IV
$random = CryptoFactory::createRandom();
$key = $random->getRandomBytes($cipher->getKeyLength());
$iv = $random->getRandomBytes($cipher->getIVLength());

// 加密数据
$plaintext = 'Secret message';
$aad = 'Additional authenticated data';
$tag = null;
$ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

// 解密数据
$decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);
```

### HKDF密钥导出

```php
use Tourze\TLSCrypto\CryptoFactory;

// 创建基于SHA-256的HKDF
$kdf = CryptoFactory::createKdf('hkdf-sha256');

// 导出密钥
$secret = 'Master secret';
$salt = 'Salt value';
$info = 'Key expansion';
$length = 32; // 导出32字节的密钥材料
$derivedKey = $kdf->derive($secret, $salt, $info, $length);
```

## 许可证

本项目采用MIT许可证，详情请查看[LICENSE](LICENSE)文件。
