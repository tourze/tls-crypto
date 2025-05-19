<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Contract;

/**
 * 哈希函数接口
 */
interface HashInterface
{
    /**
     * 获取哈希算法名称
     *
     * @return string
     */
    public function getName(): string;

    /**
     * 获取哈希输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int;

    /**
     * 获取哈希块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int;

    /**
     * 计算数据的哈希值
     *
     * @param string $data 要计算哈希的数据
     * @return string 哈希值
     */
    public function hash(string $data): string;

    /**
     * 创建哈希上下文
     *
     * @return resource|object 哈希上下文
     */
    public function createContext();

    /**
     * 更新哈希上下文
     *
     * @param resource|object $context 哈希上下文
     * @param string $data 要添加到哈希计算的数据
     * @return void
     */
    public function updateContext($context, string $data): void;

    /**
     * 完成哈希计算
     *
     * @param resource|object $context 哈希上下文
     * @return string 最终的哈希值
     */
    public function finalizeContext($context): string;
}
