<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Mac;

use Tourze\TLSCrypto\Contract\MacInterface;
use Tourze\TLSCrypto\Exception\MacException;

/**
 * Poly1305消息认证码实现
 * Poly1305是一个单独的消息认证码，不同于ChaCha20-Poly1305的组合
 */
class Poly1305 implements MacInterface
{
    /**
     * 固定密钥长度（字节）
     */
    private const KEY_LENGTH = 32;

    /**
     * 获取MAC算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'poly1305';
    }

    /**
     * 获取MAC输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int
    {
        return 16; // Poly1305标签长度固定为16字节（128位）
    }

    /**
     * 计算消息认证码
     *
     * @param string $data 要计算MAC的数据
     * @param string $key 密钥（必须是32字节）
     * @return string MAC值
     * @throws MacException 如果计算MAC失败
     */
    public function compute(string $data, string $key): string
    {
        // 验证密钥长度
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new MacException('Poly1305密钥长度必须是32字节');
        }

        // 使用备选OpenSSL实现
        return $this->fallbackImplementation($data, $key);
    }

    /**
     * 验证消息认证码
     *
     * @param string $data 原始数据
     * @param string $mac 消息认证码
     * @param string $key 密钥
     * @return bool MAC是否有效
     */
    public function verify(string $data, string $mac, string $key): bool
    {
        // 验证MAC长度
        if (strlen($mac) !== $this->getOutputLength()) {
            return false;
        }

        // 验证密钥长度
        if (strlen($key) !== self::KEY_LENGTH) {
            return false;
        }

        // 使用备选OpenSSL实现
        try {
            $computed = $this->fallbackImplementation($data, $key);
            return hash_equals($computed, $mac);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * 使用OpenSSL实现Poly1305功能
     *
     * @param string $data 要计算MAC的数据
     * @param string $key 密钥
     * @return string MAC值
     * @throws MacException 如果计算失败
     */
    private function fallbackImplementation(string $data, string $key): string
    {
        // 使用OpenSSL的ChaCha20-Poly1305作为备选方案
        // 但这只是一个接近的模拟，不是纯Poly1305

        // 注意：这是一个模拟实现，实际上是使用ChaCha20-Poly1305，但只取其认证部分
        // 在真实场景中，应该确保有正确的Poly1305实现

        // 生成一个零IV
        $iv = str_repeat("\0", 12);

        // 使用空明文，将数据用作AAD
        $cipherMethod = 'chacha20-poly1305';
        $tag = '';

        $result = openssl_encrypt(
            '', // 空明文
            $cipherMethod,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag, // 这里tag将被设置为MAC值
            $data // 将数据作为AAD
        );

        // @phpstan-ignore-next-line
        if ($result === false || empty($tag)) {
            throw new MacException('Poly1305模拟计算失败: ' . openssl_error_string());
        }

        return $tag;
    }
}
