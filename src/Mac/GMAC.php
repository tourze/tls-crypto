<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Mac;

use Tourze\TLSCrypto\Contract\MacInterface;
use Tourze\TLSCrypto\Exception\MacException;

/**
 * GMAC（Galois Message Authentication Code）消息认证码实现
 * GMAC是基于AES-GCM模式的认证码，但不加密数据
 */
class GMAC implements MacInterface
{
    /**
     * 密钥长度（字节）
     */
    private int $keyLength;

    /**
     * 构造函数
     *
     * @param int $keySize 密钥大小（位）
     * @throws MacException 如果密钥大小无效
     */
    public function __construct(int $keySize = 256)
    {
        // 验证密钥大小
        if (!in_array($keySize, [128, 192, 256])) {
            throw new MacException('无效的GMAC密钥大小，有效值为128、192或256位');
        }

        $this->keyLength = $keySize / 8;
    }

    /**
     * 获取MAC算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'gmac-' . ($this->keyLength * 8);
    }

    /**
     * 获取MAC输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int
    {
        return 16; // GCM/GMAC验证标签长度固定为16字节（128位）
    }

    /**
     * 计算消息认证码
     *
     * @param string $data 要计算MAC的数据
     * @param string $key 密钥
     * @return string MAC值
     * @throws MacException 如果计算MAC失败
     */
    public function compute(string $data, string $key): string
    {
        // 验证密钥长度
        if (strlen($key) !== $this->keyLength) {
            throw new MacException('密钥长度不匹配，需要' . $this->keyLength . '字节');
        }

        // 为GMAC生成随机IV（固定为12字节），在实际使用中通常需要提供固定/已知的IV
        $iv = random_bytes(12);

        // 使用空明文进行AES-GCM加密操作，将数据作为AAD
        $cipherName = 'aes-' . ($this->keyLength * 8) . '-gcm';
        $ciphertext = '';
        $tag = '';

        $result = openssl_encrypt(
            '', // 空明文（GMAC只计算MAC而不加密数据）
            $cipherName,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag, // 这里tag将被设置为MAC值
            $data, // 将要计算MAC的数据作为AAD传入
            16 // 标签长度（字节）
        );

        if ($result === false || empty($tag)) {
            throw new MacException('GMAC计算失败: ' . openssl_error_string());
        }

        // 将IV与标签一起返回，以便验证时使用
        return $iv . $tag;
    }

    /**
     * 验证消息认证码
     *
     * @param string $data 原始数据
     * @param string $mac 消息认证码（包含IV和标签）
     * @param string $key 密钥
     * @return bool MAC是否有效
     */
    public function verify(string $data, string $mac, string $key): bool
    {
        // 验证MAC长度
        $expectedLength = 12 + $this->getOutputLength(); // IV(12) + TAG(16)
        if (strlen($mac) !== $expectedLength) {
            return false;
        }
        
        // 验证密钥长度
        if (strlen($key) !== $this->keyLength) {
            return false;
        }
        
        // 从传入的MAC中提取IV和标签
        $iv = substr($mac, 0, 12);
        $tag = substr($mac, 12);
        
        $cipherName = 'aes-' . ($this->keyLength * 8) . '-gcm';
        
        // 使用相同参数进行解密操作，验证标签是否正确
        $result = openssl_decrypt(
            '', // 空密文
            $cipherName,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag, // 验证此标签
            $data // 原始AAD数据
        );
        
        // 如果解密成功（标签验证通过），则返回true
        return $result !== false;
    }
} 