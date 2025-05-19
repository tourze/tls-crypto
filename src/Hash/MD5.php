<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Hash;

use Tourze\TLSCrypto\Contract\HashInterface;
use Tourze\TLSCrypto\Exception\HashException;

/**
 * MD5哈希函数实现
 *
 * 严重安全警告：MD5被认为是完全不安全的，已被成功碰撞且计算速度非常快。
 * 它不应该用于任何安全场景，包括但不限于：
 * - 数字签名
 * - 密码存储
 * - 安全令牌
 * - 证书验证
 * - 数据完整性保护
 *
 * 此实现仅用于兼容旧系统或协议，或在不涉及安全的场景下使用。
 * 对于任何安全相关的用途，请使用SHA-256或更强的哈希函数。
 */
class MD5 implements HashInterface
{
    /**
     * 获取哈希算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'md5';
    }

    /**
     * 获取哈希输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int
    {
        return 16; // 128位 = 16字节
    }

    /**
     * 获取哈希块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int
    {
        return 64; // MD5的块大小为64字节
    }

    /**
     * 计算数据的哈希值
     *
     * @param string $data 要计算哈希的数据
     * @return string 哈希值
     */
    public function hash(string $data): string
    {
        return hash('md5', $data, true);
    }

    /**
     * 创建哈希上下文
     *
     * @return resource|object 哈希上下文
     * @throws HashException 如果创建上下文失败
     */
    public function createContext()
    {
        $context = hash_init('md5');
        if ($context === false) {
            throw new HashException('无法初始化MD5哈希上下文');
        }
        return $context;
    }

    /**
     * 更新哈希上下文
     *
     * @param resource|object $context 哈希上下文
     * @param string $data 要添加到哈希计算的数据
     * @return void
     */
    public function updateContext($context, string $data): void
    {
        hash_update($context, $data);
    }

    /**
     * 完成哈希计算
     *
     * @param resource|object $context 哈希上下文
     * @return string 最终的哈希值
     */
    public function finalizeContext($context): string
    {
        return hash_final($context, true);
    }
}
