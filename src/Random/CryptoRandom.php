<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Random;

use Tourze\TLSCrypto\Contract\RandomInterface;
use Tourze\TLSCrypto\Exception\RandomException;

/**
 * 使用PHP内置函数实现的加密安全随机数生成器
 */
class CryptoRandom implements RandomInterface
{
    /**
     * 生成指定长度的随机字节
     *
     * @param int $length 需要生成的随机字节数
     * @return string 随机字节
     * @throws RandomException 如果随机数生成失败
     */
    public function getRandomBytes(int $length): string
    {
        if ($length <= 0) {
            throw new RandomException('随机字节长度必须大于0');
        }

        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            throw new RandomException('随机字节生成失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 生成指定范围内的随机整数
     *
     * @param int $min 最小值（含）
     * @param int $max 最大值（含）
     * @return int 随机整数
     * @throws RandomException 如果随机数生成失败或参数无效
     */
    public function getRandomInt(int $min, int $max): int
    {
        if ($min > $max) {
            throw new RandomException('最小值不能大于最大值');
        }

        try {
            return random_int($min, $max);
        } catch (\Exception $e) {
            throw new RandomException('随机整数生成失败: ' . $e->getMessage(), 0, $e);
        }
    }
}
