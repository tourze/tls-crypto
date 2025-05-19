<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Curve;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Curve\Curve448;
use Tourze\TLSCrypto\Exception\CurveException;

/**
 * Curve448测试
 */
class Curve448Test extends TestCase
{
    /**
     * 测试获取曲线名称
     */
    public function testGetName(): void
    {
        $curve = new Curve448();
        $this->assertEquals('curve448', $curve->getName());
    }

    /**
     * 测试获取密钥大小
     */
    public function testGetKeySize(): void
    {
        $curve = new Curve448();
        $this->assertEquals(448, $curve->getKeySize());
    }

    /**
     * 测试生成密钥对时抛出的异常
     */
    public function testGenerateKeyPairThrowsException(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试Curve448');
        }

        $curve = new Curve448();
        $this->expectException(CurveException::class);
        $curve->generateKeyPair();
    }

    /**
     * 测试从私钥派生公钥时抛出的异常
     */
    public function testDerivePublicKeyThrowsException(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试Curve448');
        }

        $curve = new Curve448();
        $this->expectException(CurveException::class);
        $curve->derivePublicKey('dummy-private-key');
    }
}
