<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\KeyExchangeException;
use Tourze\TLSCrypto\KeyExchange\X448;

/**
 * X448密钥交换测试
 */
class X448Test extends TestCase
{
    /**
     * 测试X448算法名称
     */
    public function testGetName(): void
    {
        $x448 = new X448();
        $this->assertEquals('x448', $x448->getName());
    }

    /**
     * 测试生成密钥对时抛出的异常
     */
    public function testGenerateKeyPairThrowsException(): void
    {
        // 跳过测试，因为目前PHP不支持X448
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试X448');
        }

        $x448 = new X448();
        $this->expectException(KeyExchangeException::class);
        $x448->generateKeyPair();
    }

    /**
     * 测试计算共享密钥时抛出的异常
     */
    public function testComputeSharedSecretThrowsException(): void
    {
        // 跳过测试，因为目前PHP不支持X448
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试X448');
        }

        $x448 = new X448();
        $this->expectException(KeyExchangeException::class);
        $x448->computeSharedSecret('dummy-private-key', 'dummy-public-key');
    }
}
