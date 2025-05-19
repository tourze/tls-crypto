<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\KeyExchange;

use Tourze\TLSCrypto\Contract\KeyExchangeInterface;
use Tourze\TLSCrypto\Exception\KeyExchangeException;

/**
 * X25519密钥交换算法实现
 *
 * 基于Curve25519椭圆曲线的密钥交换算法
 */
class X25519 implements KeyExchangeInterface
{
    /**
     * 获取密钥交换算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'x25519';
    }

    /**
     * 生成密钥对
     *
     * @param array $options 生成密钥对的选项
     * @return array 包含私钥和公钥的数组
     * @throws KeyExchangeException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        // 检查sodium扩展是否加载
        if (!extension_loaded('sodium')) {
            throw new KeyExchangeException('libsodium扩展未加载，无法使用X25519');
        }

        try {
            // 生成X25519密钥对
            $privateKey = random_bytes(SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
            $publicKey = sodium_crypto_scalarmult_base($privateKey);

            return [
                'privateKey' => $privateKey,
                'publicKey' => $publicKey,
            ];
        } catch (\Exception $e) {
            throw new KeyExchangeException('X25519密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 计算共享密钥
     *
     * @param string $privateKey 本方私钥
     * @param string $publicKey 对方公钥
     * @param array $options 计算选项
     * @return string 共享密钥
     * @throws KeyExchangeException 如果计算共享密钥失败
     */
    public function computeSharedSecret(string $privateKey, string $publicKey, array $options = []): string
    {
        // 检查sodium扩展是否加载
        if (!extension_loaded('sodium')) {
            throw new KeyExchangeException('libsodium扩展未加载，无法使用X25519');
        }

        // 验证密钥长度
        if (strlen($privateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new KeyExchangeException('无效的X25519私钥长度');
        }

        if (strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new KeyExchangeException('无效的X25519公钥长度');
        }

        try {
            // 使用X25519算法计算共享密钥
            $sharedSecret = sodium_crypto_scalarmult($privateKey, $publicKey);
            return $sharedSecret;
        } catch (\SodiumException $e) {
            throw new KeyExchangeException('X25519共享密钥计算失败: ' . $e->getMessage());
        }
    }
}
