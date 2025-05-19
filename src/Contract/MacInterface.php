<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Contract;

/**
 * 消息认证码接口
 */
interface MacInterface
{
    /**
     * 获取MAC算法名称
     *
     * @return string
     */
    public function getName(): string;

    /**
     * 获取MAC输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int;

    /**
     * 计算消息认证码
     *
     * @param string $data 要计算MAC的数据
     * @param string $key 密钥
     * @return string MAC值
     */
    public function compute(string $data, string $key): string;

    /**
     * 验证消息认证码
     *
     * @param string $data 原始数据
     * @param string $mac 消息认证码
     * @param string $key 密钥
     * @return bool MAC是否有效
     */
    public function verify(string $data, string $mac, string $key): bool;
}
