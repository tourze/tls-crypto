<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Cipher;

use Tourze\TLSCrypto\Contract\CipherInterface;
use Tourze\TLSCrypto\Exception\CipherException;

/**
 * AES-CBC对称加密算法实现
 */
class AesCbc implements CipherInterface
{
    /**
     * 密钥长度（字节）
     */
    private int $keyLength;

    /**
     * 构造函数
     *
     * @param int $keySize 密钥大小（位）
     * @throws CipherException 如果密钥大小无效
     */
    public function __construct(int $keySize = 256)
    {
        // 验证密钥大小
        if (!in_array($keySize, [128, 192, 256])) {
            throw new CipherException('无效的AES密钥大小，有效值为128、192或256位');
        }

        $this->keyLength = $keySize / 8;
    }

    /**
     * 获取加密算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'aes-' . ($this->keyLength * 8) . '-cbc';
    }

    /**
     * 获取加密算法的密钥长度（字节）
     *
     * @return int
     */
    public function getKeyLength(): int
    {
        return $this->keyLength;
    }

    /**
     * 获取加密算法的IV长度（字节）
     *
     * @return int
     */
    public function getIVLength(): int
    {
        return 16; // AES块大小为16字节，CBC模式需要一个完整的块作为IV
    }

    /**
     * 获取加密算法的块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int
    {
        return 16; // AES块大小为16字节（128位）
    }

    /**
     * 加密数据
     *
     * @param string $plaintext 明文数据
     * @param string $key 密钥
     * @param string $iv 初始化向量
     * @param string|null $aad 不使用（CBC模式不支持AAD）
     * @param string|null $tag 不使用（CBC模式不输出认证标签）
     * @return string 加密后的数据
     * @throws CipherException 如果加密失败
     */
    public function encrypt(string $plaintext, string $key, string $iv, ?string $aad = null, ?string &$tag = null): string
    {
        // 验证密钥长度
        if (strlen($key) !== $this->keyLength) {
            throw new CipherException('密钥长度不匹配，需要' . $this->keyLength . '字节');
        }

        // 验证IV长度
        if (strlen($iv) !== $this->getIVLength()) {
            throw new CipherException('IV长度不匹配，需要' . $this->getIVLength() . '字节');
        }

        if ($aad !== null) {
            // CBC模式不支持AAD，忽略，但不报错
        }

        // 加密
        $cipherMethod = $this->getName();
        $result = openssl_encrypt(
            $plaintext,
            $cipherMethod,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($result === false) {
            throw new CipherException('AES-CBC加密失败: ' . openssl_error_string());
        }

        return $result;
    }

    /**
     * 解密数据
     *
     * @param string $ciphertext 密文数据
     * @param string $key 密钥
     * @param string $iv 初始化向量
     * @param string|null $aad 不使用（CBC模式不支持AAD）
     * @param string|null $tag 不使用（CBC模式不需要认证标签）
     * @return string 解密后的数据
     * @throws CipherException 如果解密失败
     */
    public function decrypt(string $ciphertext, string $key, string $iv, ?string $aad = null, ?string $tag = null): string
    {
        // 验证密钥长度
        if (strlen($key) !== $this->keyLength) {
            throw new CipherException('密钥长度不匹配，需要' . $this->keyLength . '字节');
        }

        // 验证IV长度
        if (strlen($iv) !== $this->getIVLength()) {
            throw new CipherException('IV长度不匹配，需要' . $this->getIVLength() . '字节');
        }

        if ($aad !== null || $tag !== null) {
            // CBC模式不支持AAD和认证标签，忽略，但不报错
        }

        // 解密
        $cipherMethod = $this->getName();
        $result = openssl_decrypt(
            $ciphertext,
            $cipherMethod,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($result === false) {
            throw new CipherException('AES-CBC解密失败: ' . openssl_error_string());
        }

        return $result;
    }
}
