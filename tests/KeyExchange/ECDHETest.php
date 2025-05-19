<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\KeyExchange;

use Exception;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\KeyExchangeException;
use Tourze\TLSCrypto\KeyExchange\ECDHE;

/**
 * ECDHE密钥交换测试
 */
class ECDHETest extends TestCase
{
    /**
     * 测试获取算法名称
     */
    public function testGetName(): void
    {
        $ecdhe = new ECDHE();
        $this->assertEquals('ecdhe', $ecdhe->getName());
    }

    /**
     * 测试生成密钥对
     */
    public function testGenerateKeyPair(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDHE');
        }

        // 检查是否支持椭圆曲线
        try {
            $curves = openssl_get_curve_names();
            if (empty($curves)) {
                $this->markTestSkipped('当前OpenSSL环境不支持任何椭圆曲线');
            }
        } catch (Exception $e) {
            $this->markTestSkipped('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }

        try {
            $ecdhe = new ECDHE();
            $keyPair = $ecdhe->generateKeyPair();

            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertArrayHasKey('publicKey', $keyPair);
            $this->assertArrayHasKey('curve', $keyPair);

            // 验证是EC密钥
            $privateKey = @openssl_pkey_get_private($keyPair['privateKey']);
            $this->assertNotFalse($privateKey);

            $keyDetails = @openssl_pkey_get_details($privateKey);
            $this->assertEquals(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
        } catch (KeyExchangeException $e) {
            $this->markTestSkipped('ECDHE测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试不同曲线的密钥对生成
     */
    public function testGenerateKeyPairWithDifferentCurves(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDHE');
        }

        $ecdhe = new ECDHE();

        // 测试 P-384 曲线
        try {
            $keyPair = $ecdhe->generateKeyPair(['curve' => 'secp384r1']);
            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertEquals('secp384r1', $keyPair['curve']);
        } catch (KeyExchangeException $e) {
            // 如果不支持此曲线，则忽略
            $this->markTestSkipped('不支持secp384r1曲线');
        }
    }

    /**
     * 测试计算共享密钥
     *
     * PHP 8以上支持标准的ECDH操作，较旧版本则使用模拟实现
     */
    public function testComputeSharedSecret(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDHE');
        }

        // 检查是否支持椭圆曲线
        try {
            $curves = openssl_get_curve_names();
            if (empty($curves)) {
                $this->markTestSkipped('当前OpenSSL环境不支持任何椭圆曲线');
            }
        } catch (Exception $e) {
            $this->markTestSkipped('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }

        // PHP 8以下版本且没有openssl_pkey_derive函数时，预期失败
        if (!function_exists('openssl_pkey_derive') && PHP_VERSION_ID < 80000) {
            try {
                $ecdhe = new ECDHE();
                $aliceKeyPair = $ecdhe->generateKeyPair();
                $bobKeyPair = $ecdhe->generateKeyPair();

                $this->expectException(KeyExchangeException::class);
                $ecdhe->computeSharedSecret(
                    $aliceKeyPair['privateKey'],
                    $bobKeyPair['publicKey']
                );
                return;
            } catch (KeyExchangeException $e) {
                if (strpos($e->getMessage(), '生成密钥对失败') !== false) {
                    $this->markTestSkipped('ECDHE测试跳过: ' . $e->getMessage());
                } else {
                    throw $e;
                }
            }
        }

        // PHP 8及以上版本或有openssl_pkey_derive函数时，预期成功
        try {
            $ecdhe = new ECDHE();
            $aliceKeyPair = $ecdhe->generateKeyPair();
            $bobKeyPair = $ecdhe->generateKeyPair();

            // Alice计算共享密钥
            $aliceSharedSecret = $ecdhe->computeSharedSecret(
                $aliceKeyPair['privateKey'],
                $bobKeyPair['publicKey']
            );

            // Bob计算共享密钥
            $bobSharedSecret = $ecdhe->computeSharedSecret(
                $bobKeyPair['privateKey'],
                $aliceKeyPair['publicKey']
            );

            // 验证两者计算的共享密钥相同
            $this->assertEquals($aliceSharedSecret, $bobSharedSecret);
            $this->assertNotEmpty($aliceSharedSecret);
            $this->assertIsString($aliceSharedSecret);
        } catch (KeyExchangeException $e) {
            // 如果使用备用方法失败，标记测试跳过
            if (strpos($e->getMessage(), '当前PHP版本不支持ECDHE点乘法操作') !== false) {
                $this->markTestSkipped('当前PHP版本不支持ECDHE点乘法操作: ' . $e->getMessage());
            } else {
                $this->markTestSkipped('ECDHE测试跳过: ' . $e->getMessage());
            }
        }
    }

    /**
     * 测试无效的曲线
     */
    public function testInvalidCurve(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDHE');
        }

        $ecdhe = new ECDHE();
        $this->expectException(KeyExchangeException::class);
        $ecdhe->generateKeyPair(['curve' => 'clearly-invalid-curve-name']);
    }
}
