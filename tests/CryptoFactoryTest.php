<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\AsymmetricCipher\ECDSA;
use Tourze\TLSCrypto\AsymmetricCipher\Ed25519;
use Tourze\TLSCrypto\AsymmetricCipher\RSA;
use Tourze\TLSCrypto\Cipher\AesGcm;
use Tourze\TLSCrypto\Cipher\ChaCha20Poly1305;
use Tourze\TLSCrypto\Contract\CurveInterface;
use Tourze\TLSCrypto\Contract\KeyExchangeInterface;
use Tourze\TLSCrypto\CryptoFactory;
use Tourze\TLSCrypto\Exception\CryptoException;
use Tourze\TLSCrypto\Hash\SHA256;
use Tourze\TLSCrypto\Kdf\HKDF;
use Tourze\TLSCrypto\KeyExchange\ECDHE;
use Tourze\TLSCrypto\KeyExchange\X448;
use Tourze\TLSCrypto\Mac\HMAC;
use Tourze\TLSCrypto\Random\CryptoRandom;

/**
 * CryptoFactory测试用例
 */
class CryptoFactoryTest extends TestCase
{
    /**
     * 测试创建随机数生成器
     */
    public function testCreateRandom(): void
    {
        $random = CryptoFactory::createRandom();
        $this->assertInstanceOf(CryptoRandom::class, $random);
    }

    /**
     * 测试创建哈希函数
     */
    public function testCreateHash(): void
    {
        $hash = CryptoFactory::createHash('sha256');
        $this->assertInstanceOf(SHA256::class, $hash);
        $this->assertEquals('sha256', $hash->getName());
    }

    /**
     * 测试创建不支持的哈希函数
     */
    public function testCreateHashUnsupported(): void
    {
        $this->expectException(CryptoException::class);
        CryptoFactory::createHash('unsupported');
    }

    /**
     * 测试创建MAC
     */
    public function testCreateMac(): void
    {
        $mac = CryptoFactory::createMac('hmac-sha256');
        $this->assertInstanceOf(HMAC::class, $mac);
        $this->assertEquals('hmac-sha256', $mac->getName());
    }

    /**
     * 测试创建不支持的MAC
     */
    public function testCreateMacUnsupported(): void
    {
        $this->expectException(CryptoException::class);
        CryptoFactory::createMac('unsupported');
    }

    /**
     * 测试创建密码算法
     */
    public function testCreateCipher(): void
    {
        $cipher = CryptoFactory::createCipher('aes-256-gcm');
        $this->assertInstanceOf(AesGcm::class, $cipher);
        $this->assertEquals('aes-256-gcm', $cipher->getName());
        $this->assertEquals(32, $cipher->getKeyLength()); // 256位 = 32字节
    }

    /**
     * 测试创建ChaCha20-Poly1305算法
     */
    public function testCreateChaCha20Poly1305(): void
    {
        try {
            $cipher = CryptoFactory::createCipher('chacha20-poly1305');
            $this->assertInstanceOf(ChaCha20Poly1305::class, $cipher);
            $this->assertEquals('chacha20-poly1305', $cipher->getName());
            $this->assertEquals(32, $cipher->getKeyLength()); // 256位 = 32字节
        } catch (CryptoException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试创建不支持的密码算法
     */
    public function testCreateCipherUnsupported(): void
    {
        $this->expectException(CryptoException::class);
        CryptoFactory::createCipher('unsupported');
    }

    /**
     * 测试创建KDF
     */
    public function testCreateKdf(): void
    {
        $kdf = CryptoFactory::createKdf('hkdf-sha256');
        $this->assertInstanceOf(HKDF::class, $kdf);
        $this->assertEquals('hkdf-sha256', $kdf->getName());
    }

    /**
     * 测试创建不支持的KDF
     */
    public function testCreateKdfUnsupported(): void
    {
        $this->expectException(CryptoException::class);
        CryptoFactory::createKdf('unsupported');
    }

    /**
     * 测试AES-GCM加密和解密
     */
    public function testAesGcmEncryptDecrypt(): void
    {
        $random = CryptoFactory::createRandom();
        $cipher = CryptoFactory::createCipher('aes-256-gcm');

        $key = $random->getRandomBytes($cipher->getKeyLength());
        $iv = $random->getRandomBytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';
        $aad = 'Additional Data';

        $tag = null;
        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertNotNull($tag);

        $decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * 测试ChaCha20-Poly1305加密和解密
     */
    public function testChaCha20Poly1305EncryptDecrypt(): void
    {
        try {
            $random = CryptoFactory::createRandom();
            $cipher = CryptoFactory::createCipher('chacha20-poly1305');

            $key = $random->getRandomBytes($cipher->getKeyLength());
            $iv = $random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';
            $aad = 'Additional Data';

            $tag = null;
            $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

            $this->assertNotEquals($plaintext, $ciphertext);
            $this->assertNotNull($tag);

            $decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);
            $this->assertEquals($plaintext, $decrypted);
        } catch (CryptoException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试HMAC计算和验证
     */
    public function testHmacComputeVerify(): void
    {
        $random = CryptoFactory::createRandom();
        $hmac = CryptoFactory::createMac('hmac-sha256');

        $key = $random->getRandomBytes(32);
        $data = 'Test Message';

        $mac = $hmac->compute($data, $key);
        $this->assertTrue($hmac->verify($data, $mac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $mac, $key));
    }

    /**
     * 测试HKDF密钥导出
     */
    public function testHkdfDerive(): void
    {
        $kdf = CryptoFactory::createKdf('hkdf-sha256');

        $secret = 'master secret';
        $salt = 'salt value';
        $info = 'context information';
        $length = 32;

        $key1 = $kdf->derive($secret, $salt, $info, $length);
        $key2 = $kdf->derive($secret, $salt, $info, $length);

        $this->assertEquals($length, strlen($key1));
        $this->assertEquals($key1, $key2);

        // 不同的info应该产生不同的密钥
        $key3 = $kdf->derive($secret, $salt, 'different info', $length);
        $this->assertNotEquals($key1, $key3);
    }

    /**
     * 测试创建非对称加密算法
     */
    public function testCreateAsymmetricCipher(): void
    {
        // 测试RSA
        $rsa = CryptoFactory::createAsymmetricCipher('rsa');
        $this->assertInstanceOf(RSA::class, $rsa);
        $this->assertEquals('rsa', $rsa->getName());

        // 测试Ed25519
        $ed25519 = CryptoFactory::createAsymmetricCipher('ed25519');
        $this->assertInstanceOf(Ed25519::class, $ed25519);
        $this->assertEquals('ed25519', $ed25519->getName());

        // 测试ECDSA
        $ecdsa = CryptoFactory::createAsymmetricCipher('ecdsa');
        $this->assertInstanceOf(ECDSA::class, $ecdsa);
        $this->assertEquals('ecdsa', $ecdsa->getName());

        // 测试不支持的算法
        $this->expectException(CryptoException::class);
        CryptoFactory::createAsymmetricCipher('unsupported');
    }

    /**
     * 测试创建密钥交换算法
     */
    public function testCreateKeyExchange(): void
    {
        // 测试X25519
        $keyExchange = CryptoFactory::createKeyExchange('x25519');
        $this->assertInstanceOf(KeyExchangeInterface::class, $keyExchange);
        $this->assertEquals('x25519', $keyExchange->getName());

        // 测试X448
        $keyExchange = CryptoFactory::createKeyExchange('x448');
        $this->assertInstanceOf(X448::class, $keyExchange);
        $this->assertEquals('x448', $keyExchange->getName());

        // 测试ECDHE
        $keyExchange = CryptoFactory::createKeyExchange('ecdhe');
        $this->assertInstanceOf(ECDHE::class, $keyExchange);
        $this->assertEquals('ecdhe', $keyExchange->getName());

        // 测试不支持的算法
        $this->expectException(CryptoException::class);
        CryptoFactory::createKeyExchange('unsupported-key-exchange');
    }

    /**
     * 测试创建椭圆曲线
     */
    public function testCreateCurve(): void
    {
        // 测试P-256
        $curve = CryptoFactory::createCurve('p-256');
        $this->assertInstanceOf(CurveInterface::class, $curve);
        $this->assertEquals('nistp256', $curve->getName());

        // 测试NIST P-256
        $curve = CryptoFactory::createCurve('nistp256');
        $this->assertInstanceOf(CurveInterface::class, $curve);
        $this->assertEquals('nistp256', $curve->getName());

        // 测试Curve25519
        $curve = CryptoFactory::createCurve('curve25519');
        $this->assertInstanceOf(CurveInterface::class, $curve);
        $this->assertEquals('curve25519', $curve->getName());

        // 测试Curve448
        $curve = CryptoFactory::createCurve('curve448');
        $this->assertInstanceOf(CurveInterface::class, $curve);
        $this->assertEquals('curve448', $curve->getName());

        // 测试不支持的曲线
        $this->expectException(CryptoException::class);
        CryptoFactory::createCurve('unsupported-curve');
    }
}
