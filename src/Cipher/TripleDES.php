<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Cipher;

use Tourze\TLSCrypto\Contract\CipherInterface;
use Tourze\TLSCrypto\Exception\CipherException;

/**
 * 3DES (Triple DES) 对称加密算法实现
 * 实现了CBC模式的3DES
 */
class TripleDES implements CipherInterface
{
    /**
     * 密钥长度（字节）
     */
    private int $keyLength;

    /**
     * 构造函数
     *
     * @param int $keySize 密钥大小（位），3DES支持128位（仅用于兼容）和192位
     * @throws CipherException 如果密钥大小无效
     */
    public function __construct(int $keySize = 192)
    {
        // 验证密钥大小
        if (!in_array($keySize, [128, 192])) {
            throw new CipherException('无效的3DES密钥大小，有效值为128或192位');
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
        if ($this->keyLength === 16) {
            return 'des-ede-cbc'; // 128位密钥（实际使用时，第三个DES使用第一个DES的密钥）
        }
        return 'des-ede3-cbc'; // 192位密钥（完整的3DES）
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
        return 8; // DES块大小为8字节，3DES CBC模式需要一个完整的块作为IV
    }

    /**
     * 获取加密算法的块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int
    {
        return 8; // DES/3DES块大小为8字节（64位）
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
            throw new CipherException('3DES加密失败: ' . openssl_error_string());
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
            throw new CipherException('3DES解密失败: ' . openssl_error_string());
        }

        return $result;
    }
}
