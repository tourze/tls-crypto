<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Contract;

/**
 * 对称加密算法接口
 */
interface CipherInterface
{
    /**
     * 获取加密算法名称
     *
     * @return string
     */
    public function getName(): string;

    /**
     * 获取加密算法的密钥长度（字节）
     *
     * @return int
     */
    public function getKeyLength(): int;

    /**
     * 获取加密算法的IV长度（字节）
     *
     * @return int
     */
    public function getIVLength(): int;

    /**
     * 获取加密算法的块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int;

    /**
     * 加密数据
     *
     * @param string $plaintext 明文数据
     * @param string $key 密钥
     * @param string $iv 初始化向量
     * @param string|null $aad 附加认证数据（仅AEAD模式使用）
     * @param string|null $tag 认证标签（输出参数，仅AEAD模式使用）
     * @return string 加密后的数据
     */
    public function encrypt(string $plaintext, string $key, string $iv, ?string $aad = null, ?string &$tag = null): string;

    /**
     * 解密数据
     *
     * @param string $ciphertext 密文数据
     * @param string $key 密钥
     * @param string $iv 初始化向量
     * @param string|null $aad 附加认证数据（仅AEAD模式使用）
     * @param string|null $tag 认证标签（仅AEAD模式使用）
     * @return string 解密后的数据
     */
    public function decrypt(string $ciphertext, string $key, string $iv, ?string $aad = null, ?string $tag = null): string;
}
