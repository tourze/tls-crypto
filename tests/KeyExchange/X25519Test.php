<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\KeyExchange\X25519;

/**
 * X25519密钥交换测试
 */
class X25519Test extends TestCase
{
    /**
     * 测试X25519密钥交换
     */
    public function testX25519KeyExchange(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试X25519');
        }

        $x25519 = new X25519();

        // 测试算法名称
        $this->assertEquals('x25519', $x25519->getName());

        // 生成Alice的密钥对
        $aliceKeyPair = $x25519->generateKeyPair();
        $this->assertArrayHasKey('privateKey', $aliceKeyPair);
        $this->assertArrayHasKey('publicKey', $aliceKeyPair);
        $this->assertEquals(SODIUM_CRYPTO_BOX_SECRETKEYBYTES, strlen($aliceKeyPair['privateKey']));
        $this->assertEquals(SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, strlen($aliceKeyPair['publicKey']));

        // 生成Bob的密钥对
        $bobKeyPair = $x25519->generateKeyPair();
        $this->assertArrayHasKey('privateKey', $bobKeyPair);
        $this->assertArrayHasKey('publicKey', $bobKeyPair);

        // 计算共享密钥
        $aliceSharedSecret = $x25519->computeSharedSecret(
            $aliceKeyPair['privateKey'],
            $bobKeyPair['publicKey']
        );

        $bobSharedSecret = $x25519->computeSharedSecret(
            $bobKeyPair['privateKey'],
            $aliceKeyPair['publicKey']
        );

        // 验证两边计算的共享密钥相同
        $this->assertEquals($aliceSharedSecret, $bobSharedSecret);
        $this->assertEquals(SODIUM_CRYPTO_BOX_SECRETKEYBYTES, strlen($aliceSharedSecret));
    }
}
