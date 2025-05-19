<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\AsymmetricCipher;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\AsymmetricCipher\Ed25519;
use Tourze\TLSCrypto\Exception\AsymmetricCipherException;

/**
 * Ed25519签名算法测试
 */
class Ed25519Test extends TestCase
{
    /**
     * 测试获取算法名称
     */
    public function testGetName(): void
    {
        $ed25519 = new Ed25519();
        $this->assertEquals('ed25519', $ed25519->getName());
    }

    /**
     * 测试生成密钥对
     */
    public function testGenerateKeyPair(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $keyPair = $ed25519->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertEquals(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, strlen($keyPair['privateKey']));
        $this->assertEquals(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($keyPair['publicKey']));
    }

    /**
     * 测试Ed25519签名和验证
     */
    public function testSignAndVerify(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $keyPair = $ed25519->generateKeyPair();
        $privateKey = $keyPair['privateKey'];
        $publicKey = $keyPair['publicKey'];

        $message = 'Hello, Ed25519!';

        // 签名
        $signature = $ed25519->sign($message, $privateKey);
        $this->assertEquals(SODIUM_CRYPTO_SIGN_BYTES, strlen($signature));

        // 验证有效签名
        $valid = $ed25519->verify($message, $signature, $publicKey);
        $this->assertTrue($valid);

        // 验证无效签名 - 修改消息
        $valid = $ed25519->verify('Modified message', $signature, $publicKey);
        $this->assertFalse($valid);

        // 验证无效签名 - 修改签名
        $tamperedSignature = $signature;
        $tamperedSignature[0] = chr(ord($tamperedSignature[0]) ^ 1); // 翻转一个比特
        $valid = $ed25519->verify($message, $tamperedSignature, $publicKey);
        $this->assertFalse($valid);
    }

    /**
     * 测试加密操作是否抛出异常
     */
    public function testEncryptThrowsException(): void
    {
        $ed25519 = new Ed25519();
        $this->expectException(AsymmetricCipherException::class);
        $ed25519->encrypt('test', 'dummy-key');
    }

    /**
     * 测试解密操作是否抛出异常
     */
    public function testDecryptThrowsException(): void
    {
        $ed25519 = new Ed25519();
        $this->expectException(AsymmetricCipherException::class);
        $ed25519->decrypt('test', 'dummy-key');
    }

    /**
     * 测试签名无效私钥
     */
    public function testSignWithInvalidPrivateKey(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $this->expectException(AsymmetricCipherException::class);
        $ed25519->sign('test', 'invalid-key');
    }

    /**
     * 测试验证无效公钥
     */
    public function testVerifyWithInvalidPublicKey(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $this->expectException(AsymmetricCipherException::class);
        $ed25519->verify('test', str_repeat('a', SODIUM_CRYPTO_SIGN_BYTES), 'invalid-key');
    }

    /**
     * 测试验证无效签名
     */
    public function testVerifyWithInvalidSignature(): void
    {
        // 如果sodium扩展未加载，则跳过测试
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium扩展未加载，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $keyPair = $ed25519->generateKeyPair();
        $publicKey = $keyPair['publicKey'];

        $this->expectException(AsymmetricCipherException::class);
        $ed25519->verify('test', 'invalid-signature', $publicKey);
    }
} 