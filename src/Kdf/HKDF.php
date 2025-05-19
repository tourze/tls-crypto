<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Kdf;

use Tourze\TLSCrypto\Contract\HashInterface;
use Tourze\TLSCrypto\Contract\KdfInterface;
use Tourze\TLSCrypto\Exception\KdfException;

/**
 * HKDF（HMAC-based Key Derivation Function）密钥导出函数实现
 * 参考RFC 5869: https://tools.ietf.org/html/rfc5869
 */
class HKDF implements KdfInterface
{
    /**
     * 构造函数
     *
     * @param HashInterface $hash 使用的哈希函数
     */
    public function __construct(private readonly HashInterface $hash)
    {
    }

    /**
     * 获取KDF算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'hkdf-' . $this->hash->getName();
    }

    /**
     * 从主密钥导出密钥材料
     *
     * @param string $secret 输入密钥材料
     * @param string $salt 盐值
     * @param string $info 上下文信息
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

        $hashLen = $this->hash->getOutputLength();
        if ($length > 255 * $hashLen) {
            throw new KdfException('请求的密钥长度过长，超过了255 * 哈希输出长度');
        }

        // 第1步：提取（Extract）
        $prk = $this->extract($secret, $salt);

        // 第2步：扩展（Expand）
        return $this->expand($prk, $info, $length);
    }

    /**
     * HKDF提取阶段
     *
     * @param string $ikm 输入密钥材料
     * @param string $salt 盐值
     * @return string 伪随机密钥
     */
    private function extract(string $ikm, string $salt): string
    {
        // 如果盐值为空，使用全0填充的哈希长度字符串
        if (empty($salt)) {
            $salt = str_repeat("\0", $this->hash->getOutputLength());
        }

        return hash_hmac($this->hash->getName(), $ikm, $salt, true);
    }

    /**
     * HKDF扩展阶段
     *
     * @param string $prk 伪随机密钥
     * @param string $info 上下文信息
     * @param int $length 需要导出的密钥长度
     * @return string 导出的密钥材料
     */
    private function expand(string $prk, string $info, int $length): string
    {
        $hashLen = $this->hash->getOutputLength();
        $iterations = ceil($length / $hashLen);
        $t = '';
        $okm = '';
        
        for ($i = 1; $i <= $iterations; $i++) {
            $data = $t . $info . chr($i);
            $t = hash_hmac($this->hash->getName(), $data, $prk, true);
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }
}
