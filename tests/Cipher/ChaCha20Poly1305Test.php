<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Cipher;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Cipher\ChaCha20Poly1305;
use Tourze\TLSCrypto\Exception\CipherException;
use Tourze\TLSCrypto\Random\CryptoRandom;

/**
 * ChaCha20-Poly1305测试类
 */
class ChaCha20Poly1305Test extends TestCase
{
    private CryptoRandom $random;

    /**
     * 测试基本属性
     */
    public function testBasicProperties(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            // 测试获取名称
            $this->assertEquals('chacha20-poly1305', $cipher->getName());

            // 测试获取密钥长度
            $this->assertEquals(32, $cipher->getKeyLength()); // 256位 = 32字节

            // 测试获取IV长度
            $this->assertEquals(12, $cipher->getIVLength());

            // 测试获取块大小
            $this->assertEquals(1, $cipher->getBlockSize()); // 流密码
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试加密和解密
     */
    public function testEncryptDecrypt(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            $key = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';
            $aad = 'Additional Data';

            $tag = null;
            $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

            $this->assertNotEmpty($ciphertext);
            $this->assertNotEquals($plaintext, $ciphertext);
            $this->assertNotNull($tag);
            $this->assertNotEmpty($tag);

            $decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);
            $this->assertEquals($plaintext, $decrypted);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试不同密钥的加密结果不同
     */
    public function testDifferentKeys(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            $key1 = $this->random->getRandomBytes($cipher->getKeyLength());
            $key2 = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';

            $tag1 = null;
            $ciphertext1 = $cipher->encrypt($plaintext, $key1, $iv, null, $tag1);

            $tag2 = null;
            $ciphertext2 = $cipher->encrypt($plaintext, $key2, $iv, null, $tag2);

            $this->assertNotEquals($ciphertext1, $ciphertext2);
            $this->assertNotEquals($tag1, $tag2);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试不同IV的加密结果不同
     */
    public function testDifferentIVs(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            $key = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv1 = $this->random->getRandomBytes($cipher->getIVLength());
            $iv2 = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';

            $tag1 = null;
            $ciphertext1 = $cipher->encrypt($plaintext, $key, $iv1, null, $tag1);

            $tag2 = null;
            $ciphertext2 = $cipher->encrypt($plaintext, $key, $iv2, null, $tag2);

            $this->assertNotEquals($ciphertext1, $ciphertext2);
            $this->assertNotEquals($tag1, $tag2);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试篡改密文后解密失败
     */
    public function testTamperedCiphertext(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            $key = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';

            $tag = null;
            $ciphertext = $cipher->encrypt($plaintext, $key, $iv, null, $tag);

            // 篡改密文
            $tamperedCiphertext = $ciphertext;
            $tamperedCiphertext[0] = chr(ord($tamperedCiphertext[0]) ^ 1);

            $this->expectException(CipherException::class);
            $cipher->decrypt($tamperedCiphertext, $key, $iv, null, $tag);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试篡改AAD后解密失败
     */
    public function testTamperedAAD(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            $key = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';
            $aad = 'Additional Data';

            $tag = null;
            $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

            $this->expectException(CipherException::class);
            $cipher->decrypt($ciphertext, $key, $iv, 'Tampered AAD', $tag);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试篡改TAG后解密失败
     */
    public function testTamperedTag(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            $key = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';

            $tag = null;
            $ciphertext = $cipher->encrypt($plaintext, $key, $iv, null, $tag);

            // 篡改TAG
            $tamperedTag = $tag;
            $tamperedTag[0] = chr(ord($tamperedTag[0]) ^ 1);

            $this->expectException(CipherException::class);
            $cipher->decrypt($ciphertext, $key, $iv, null, $tamperedTag);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试无TAG解密失败
     */
    public function testMissingTag(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();

            $key = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';

            $tag = null;
            $ciphertext = $cipher->encrypt($plaintext, $key, $iv, null, $tag);

            $this->expectException(CipherException::class);
            $cipher->decrypt($ciphertext, $key, $iv, null, null);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试密钥长度不匹配异常
     */
    public function testInvalidKeyLength(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();
            $key = $this->random->getRandomBytes($cipher->getKeyLength() - 1); // 少一个字节
            $iv = $this->random->getRandomBytes($cipher->getIVLength());
            $plaintext = 'Hello, World!';

            $this->expectException(CipherException::class);
            $cipher->encrypt($plaintext, $key, $iv);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    /**
     * 测试IV长度不匹配异常
     */
    public function testInvalidIVLength(): void
    {
        try {
            $cipher = new ChaCha20Poly1305();
            $key = $this->random->getRandomBytes($cipher->getKeyLength());
            $iv = $this->random->getRandomBytes($cipher->getIVLength() - 1); // 少一个字节
            $plaintext = 'Hello, World!';

            $this->expectException(CipherException::class);
            $cipher->encrypt($plaintext, $key, $iv);
        } catch (CipherException $e) {
            if (strpos($e->getMessage(), '不支持ChaCha20-Poly1305加密算法') !== false) {
                $this->markTestSkipped('当前PHP环境不支持ChaCha20-Poly1305算法');
            } else {
                throw $e;
            }
        }
    }

    protected function setUp(): void
    {
        $this->random = new CryptoRandom();
    }
}
