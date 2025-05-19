<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Kdf;

use Tourze\TLSCrypto\Contract\HashInterface;
use Tourze\TLSCrypto\Contract\KdfInterface;
use Tourze\TLSCrypto\Exception\KdfException;

/**
 * PBKDF2（Password-Based Key Derivation Function 2）密钥导出函数实现
 * 参考RFC 8018: https://tools.ietf.org/html/rfc8018
 */
class PBKDF2 implements KdfInterface
{
    /**
     * 构造函数
     *
     * @param HashInterface $hash 使用的哈希函数
     * @param int $iterations 迭代次数
     */
    public function __construct(
        private readonly HashInterface $hash,
        private readonly int $iterations = 10000
    ) {
        if ($iterations < 1000) {
            throw new KdfException('迭代次数应至少为1000以确保安全性');
        }
    }

    /**
     * 获取KDF算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'pbkdf2-' . $this->hash->getName();
    }

    /**
     * 从密码导出密钥材料
     *
     * @param string $secret 密码
     * @param string $salt 盐值
     * @param string $info 上下文信息（PBKDF2不使用此参数，但为了兼容接口保留）
     * @param int $length 需要导出的密钥长度（字节）
     * @return string 导出的密钥材料
     * @throws KdfException 如果密钥导出失败
     */
    public function derive(string $secret, string $salt, string $info, int $length): string
    {
        // 参数验证
        if ($length <= 0) {
            throw new KdfException('导出的密钥长度必须大于0');
        }

        if (empty($salt)) {
            throw new KdfException('盐值不能为空');
        }

        // 尝试使用PHP内置函数
        if (function_exists('hash_pbkdf2')) {
            return hash_pbkdf2(
                $this->hash->getName(),
                $secret,
                $salt,
                $this->iterations,
                $length,
                true
            );
        }

        // 如果内置函数不可用，手动实现PBKDF2
        return $this->pbkdf2Implementation($secret, $salt, $length);
    }

    /**
     * 手动实现PBKDF2
     *
     * @param string $password 密码
     * @param string $salt 盐值
     * @param int $keyLength 密钥长度
     * @return string 导出的密钥材料
     */
    private function pbkdf2Implementation(string $password, string $salt, int $keyLength): string
    {
        $hashLength = $this->hash->getOutputLength();
        $blockCount = ceil($keyLength / $hashLength);
        $output = '';

        for ($i = 1; $i <= $blockCount; $i++) {
            // 初始化U_1 = PRF(Password, Salt || INT_32_BE(i))
            $block = $u = hash_hmac(
                $this->hash->getName(),
                $salt . pack('N', $i),
                $password,
                true
            );

            // U_2 through U_c
            for ($j = 1; $j < $this->iterations; $j++) {
                $u = hash_hmac($this->hash->getName(), $u, $password, true);
                $block ^= $u;
            }

            $output .= $block;
        }

        return substr($output, 0, $keyLength);
    }
}
