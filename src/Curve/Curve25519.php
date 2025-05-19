<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Curve;

use Tourze\TLSCrypto\Contract\CurveInterface;
use Tourze\TLSCrypto\Exception\CurveException;

/**
 * Curve25519 椭圆曲线实现
 */
class Curve25519 implements CurveInterface
{
    /**
     * 密钥大小（位）
     */
    private const KEY_SIZE = 256;
    
    /**
     * 获取曲线名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'curve25519';
    }

    /**
     * 获取曲线的密钥大小（位）
     *
     * @return int
     */
    public function getKeySize(): int
    {
        return self::KEY_SIZE;
    }

    /**
     * 生成密钥对
     *
     * @return array 包含私钥和公钥的数组
     * @throws CurveException 如果生成密钥对失败
     */
    public function generateKeyPair(): array
    {
        // 检查sodium扩展是否加载
        if (!extension_loaded('sodium')) {
            throw new CurveException('libsodium扩展未加载，无法使用Curve25519');
        }
        
        try {
            // 生成X25519密钥对（用于DH密钥交换）
            $privateKey = sodium_crypto_box_keypair();
            $publicKey = sodium_crypto_box_publickey($privateKey);
            $secretKey = sodium_crypto_box_secretkey($privateKey);
            
            // 返回二进制格式的密钥对
            return [
                'privateKey' => $secretKey,
                'publicKey' => $publicKey,
            ];
        } catch (\SodiumException $e) {
            throw new CurveException('Curve25519密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 从私钥生成公钥
     *
     * @param string $privateKey 私钥（二进制格式）
     * @return string 公钥（二进制格式）
     * @throws CurveException 如果生成公钥失败
     */
    public function derivePublicKey(string $privateKey): string
    {
        // 检查sodium扩展是否加载
        if (!extension_loaded('sodium')) {
            throw new CurveException('libsodium扩展未加载，无法使用Curve25519');
        }
        
        // 验证私钥长度
        if (strlen($privateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new CurveException('无效的Curve25519私钥长度');
        }
        
        try {
            // 从私钥创建临时密钥对，然后提取公钥
            $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $privateKey,
                sodium_crypto_scalarmult_base($privateKey)
            );
            
            return sodium_crypto_box_publickey($keypair);
        } catch (\SodiumException $e) {
            throw new CurveException('Curve25519公钥派生失败: ' . $e->getMessage());
        }
    }
} 