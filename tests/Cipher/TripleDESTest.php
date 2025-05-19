<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Cipher;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Cipher\TripleDES;
use Tourze\TLSCrypto\Exception\CipherException;

class TripleDESTest extends TestCase
{
    public function testGetName(): void
    {
        $cipher128 = new TripleDES(128);
        $this->assertEquals('des-ede-cbc', $cipher128->getName());

        $cipher192 = new TripleDES(192);
        $this->assertEquals('des-ede3-cbc', $cipher192->getName());
    }

    public function testGetKeyLength(): void
    {
        $cipher128 = new TripleDES(128);
        $this->assertEquals(16, $cipher128->getKeyLength());

        $cipher192 = new TripleDES(192);
        $this->assertEquals(24, $cipher192->getKeyLength());
    }

    public function testGetIVLength(): void
    {
        $cipher = new TripleDES();
        $this->assertEquals(8, $cipher->getIVLength());
    }

    public function testGetBlockSize(): void
    {
        $cipher = new TripleDES();
        $this->assertEquals(8, $cipher->getBlockSize());
    }

    public function testEncryptAndDecrypt192Bit(): void
    {
        $cipher = new TripleDES(192);
        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'This is a test string for TripleDES encryption.';

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv);
        $this->assertNotEmpty($ciphertext);
        $this->assertNotEquals($plaintext, $ciphertext);

        $decryptedText = $cipher->decrypt($ciphertext, $key, $iv);
        $this->assertEquals($plaintext, $decryptedText);
    }

    public function testEncryptAndDecrypt128Bit(): void
    {
        $cipher = new TripleDES(128);
        $key = random_bytes($cipher->getKeyLength()); // 16 bytes for 128-bit 3DES
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'Another test for 128-bit 3DES.';

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv);
        $this->assertNotEmpty($ciphertext);
        $this->assertNotEquals($plaintext, $ciphertext);

        $decryptedText = $cipher->decrypt($ciphertext, $key, $iv);
        $this->assertEquals($plaintext, $decryptedText);
    }

    public function testEncryptWithInvalidKeyLength(): void
    {
        $this->expectException(CipherException::class);
        $this->expectExceptionMessage('密钥长度不匹配，需要24字节');

        $cipher = new TripleDES(192);
        $key = random_bytes(16); // Invalid length
        $iv = random_bytes($cipher->getIVLength());
        $cipher->encrypt('test', $key, $iv);
    }

    public function testEncryptWithInvalidIVLength(): void
    {
        $this->expectException(CipherException::class);
        $this->expectExceptionMessage('IV长度不匹配，需要8字节');

        $cipher = new TripleDES(192);
        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes(7); // Invalid length
        $cipher->encrypt('test', $key, $iv);
    }

    public function testDecryptWithInvalidKeyLength(): void
    {
        $this->expectException(CipherException::class);
        $this->expectExceptionMessage('密钥长度不匹配，需要24字节');

        $cipher = new TripleDES(192);
        $key = random_bytes(16); // Invalid length
        $iv = random_bytes($cipher->getIVLength());
        $cipher->decrypt('testciphertext', $key, $iv);
    }

    public function testDecryptWithInvalidIVLength(): void
    {
        $this->expectException(CipherException::class);
        $this->expectExceptionMessage('IV长度不匹配，需要8字节');

        $cipher = new TripleDES(192);
        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes(7); // Invalid length
        $cipher->decrypt('testciphertext', $key, $iv);
    }

    public function testConstructorWithInvalidKeySize(): void
    {
        $this->expectException(CipherException::class);
        $this->expectExceptionMessage('无效的3DES密钥大小，有效值为128或192位');
        new TripleDES(64);
    }
}
