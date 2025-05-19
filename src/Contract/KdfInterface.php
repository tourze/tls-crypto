<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Contract;

/**
 * 密钥导出函数接口
 */
interface KdfInterface
{
    /**
     * 获取KDF算法名称
     *
     * @return string
     */
    public function getName(): string;

    /**
     * 从主密钥导出密钥材料
     *
     * @param string $secret 输入密钥材料
     * @param string $salt 盐值
     * @param string $info 上下文信息
     * @param int $length 需要导出的密钥长度（字节）
     * @return string 导出的密钥材料
     */
    public function derive(string $secret, string $salt, string $info, int $length): string;
}
