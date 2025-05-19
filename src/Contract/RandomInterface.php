<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Contract;

/**
 * 随机数生成器接口
 */
interface RandomInterface
{
    /**
     * 生成指定长度的随机字节
     *
     * @param int $length 需要生成的随机字节数
     * @return string 随机字节
     */
    public function getRandomBytes(int $length): string;

    /**
     * 生成指定范围内的随机整数
     *
     * @param int $min 最小值（含）
     * @param int $max 最大值（含）
     * @return int 随机整数
     */
    public function getRandomInt(int $min, int $max): int;
}
