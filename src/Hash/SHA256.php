<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Hash;

use Tourze\TLSCrypto\Contract\HashInterface;
use Tourze\TLSCrypto\Exception\HashException;

/**
 * SHA-256哈希函数实现
 */
class SHA256 implements HashInterface
{
    /**
     * 获取哈希算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'sha256';
    }

    /**
     * 获取哈希输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int
    {
        return 32; // 256位 = 32字节
    }

    /**
     * 获取哈希块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int
    {
        return 64; // SHA-256的块大小为64字节
    }

    /**
     * 计算数据的哈希值
     *
     * @param string $data 要计算哈希的数据
     * @return string 哈希值
     */
    public function hash(string $data): string
    {
        return hash('sha256', $data, true);
    }

    /**
     * 创建哈希上下文
     *
     * @return resource|object 哈希上下文
     * @throws HashException 如果创建上下文失败
     */
    public function createContext()
    {
        $context = hash_init('sha256');
        if ($context === false) {
            throw new HashException('无法初始化SHA-256哈希上下文');
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
