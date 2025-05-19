<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Cipher;

use Tourze\TLSCrypto\Contract\CipherInterface;
use Tourze\TLSCrypto\Exception\CipherException;

/**
 * ChaCha20-Poly1305对称加密算法实现
 */
class ChaCha20Poly1305 implements CipherInterface
{
    /**
     * 密钥长度（字节）
     */
    private const KEY_LENGTH = 32; // 256位

    /**
     * IV长度（字节）
     */
    private const IV_LENGTH = 12; // 96位

    /**
     * 认证标签长度（字节）
     */
    private const TAG_LENGTH = 16; // 128位

    /**
     * 获取加密算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'chacha20-poly1305';
    }

    /**
     * 获取加密算法的密钥长度（字节）
     *
     * @return int
     */
    public function getKeyLength(): int
    {
        return self::KEY_LENGTH;
    }

    /**
     * 获取加密算法的IV长度（字节）
     *
     * @return int
     */
    public function getIVLength(): int
    {
        return self::IV_LENGTH;
    }

    /**
     * 获取加密算法的块大小（字节）
     * ChaCha20是流密码，没有固定的块大小，但为了兼容接口，返回1
     *
     * @return int
     */
    public function getBlockSize(): int
    {
        return 1;
    }

    /**
     * 加密数据
     *
     * @param string $plaintext 明文数据
     * @param string $key 密钥
     * @param string $iv 初始化向量
     * @param string|null $aad 附加认证数据
     * @param string|null $tag 认证标签（输出参数）
     * @return string 加密后的数据
     * @throws CipherException 如果加密失败
     */
    public function encrypt(string $plaintext, string $key, string $iv, ?string $aad = null, ?string &$tag = null): string
    {
        // 验证密钥长度
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new CipherException('密钥长度不匹配，需要' . self::KEY_LENGTH . '字节');
        }

        // 验证IV长度
        if (strlen($iv) !== self::IV_LENGTH) {
            throw new CipherException('IV长度不匹配，需要' . self::IV_LENGTH . '字节');
        }

        // 检查是否支持ChaCha20-Poly1305
        if (!in_array('chacha20-poly1305', openssl_get_cipher_methods())) {
            throw new CipherException('当前PHP环境不支持ChaCha20-Poly1305加密算法');
        }

        $tag = '';
        $result = openssl_encrypt(
            $plaintext,
            'chacha20-poly1305',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad ?? '',
            self::TAG_LENGTH
        );

        if ($result === false) {
            throw new CipherException('ChaCha20-Poly1305加密失败: ' . openssl_error_string());
        }

        return $result;
    }

    /**
     * 解密数据
     *
     * @param string $ciphertext 密文数据
     * @param string $key 密钥
     * @param string $iv 初始化向量
     * @param string|null $aad 附加认证数据
     * @param string|null $tag 认证标签
     * @return string 解密后的数据
     * @throws CipherException 如果解密失败
     */
    public function decrypt(string $ciphertext, string $key, string $iv, ?string $aad = null, ?string $tag = null): string
    {
        // 验证密钥长度
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new CipherException('密钥长度不匹配，需要' . self::KEY_LENGTH . '字节');
        }

        // 验证IV长度
        if (strlen($iv) !== self::IV_LENGTH) {
            throw new CipherException('IV长度不匹配，需要' . self::IV_LENGTH . '字节');
        }

        // 认证标签是必需的
        if ($tag === null) {
            throw new CipherException('ChaCha20-Poly1305解密需要认证标签');
        }

        // 检查是否支持ChaCha20-Poly1305
        if (!in_array('chacha20-poly1305', openssl_get_cipher_methods())) {
            throw new CipherException('当前PHP环境不支持ChaCha20-Poly1305加密算法');
        }

        $result = openssl_decrypt(
            $ciphertext,
            'chacha20-poly1305',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad ?? ''
        );

        if ($result === false) {
            throw new CipherException('ChaCha20-Poly1305解密失败: ' . openssl_error_string());
        }

        return $result;
    }
}
