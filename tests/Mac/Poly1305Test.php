<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Mac;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\MacException;
use Tourze\TLSCrypto\Mac\Poly1305;

class Poly1305Test extends TestCase
{
    public function testGetName(): void
    {
        $poly1305 = new Poly1305();
        $this->assertEquals('poly1305', $poly1305->getName());
    }

    public function testGetOutputLength(): void
    {
        $poly1305 = new Poly1305();
        $this->assertEquals(16, $poly1305->getOutputLength());
    }

    public function testComputeAndVerify(): void
    {
        // 这个测试主要验证 Poly1305 类的接口行为
        // 其内部实现会回退到 chacha20-poly1305 (OpenSSL)
        $poly1305 = new Poly1305();
        $key = random_bytes(32); // Poly1305 key is 32 bytes
        $data = 'This is the data to authenticate with Poly1305.';

        $mac = $poly1305->compute($data, $key);
        $this->assertEquals(16, strlen($mac));

        $this->assertTrue($poly1305->verify($data, $mac, $key));
    }

    public function testVerifyWithIncorrectMac(): void
    {
        $poly1305 = new Poly1305();
        $key = random_bytes(32);
        $data = 'Some data for Poly1305.';

        $correctMac = $poly1305->compute($data, $key);
        $incorrectMac = random_bytes(16);
        $this->assertNotEquals($correctMac, $incorrectMac);

        $this->assertFalse($poly1305->verify($data, $incorrectMac, $key));
    }

    public function testVerifyWithIncorrectKey(): void
    {
        $poly1305 = new Poly1305();
        $key1 = random_bytes(32);
        $key2 = random_bytes(32);
        $this->assertNotEquals($key1, $key2);
        $data = 'Some important data for Poly1305.';

        $mac = $poly1305->compute($data, $key1);
        $this->assertFalse($poly1305->verify($data, $mac, $key2));
    }

    public function testVerifyWithCorruptedData(): void
    {
        $poly1305 = new Poly1305();
        $key = random_bytes(32);
        $data = 'Original Poly1305 Data';
        $corruptedData = 'Corrupted Poly1305 Data';

        $mac = $poly1305->compute($data, $key);
        $this->assertFalse($poly1305->verify($corruptedData, $mac, $key));
    }

    public function testComputeWithInvalidKeyLength(): void
    {
        $this->expectException(MacException::class);
        $this->expectExceptionMessage('Poly1305密钥长度必须是32字节');

        $poly1305 = new Poly1305();
        $key = random_bytes(16); // Invalid length
        $poly1305->compute('testdata', $key);
    }

    public function testVerifyWithInvalidKeyLengthInVerify(): void
    {
        $poly1305 = new Poly1305();
        $key = random_bytes(32);
        $data = 'test data';
        $mac = $poly1305->compute($data, $key);

        $invalidKey = random_bytes(16); // Invalid length
        $this->assertFalse($poly1305->verify($data, $mac, $invalidKey));
    }

    public function testVerifyWithInvalidMacLength(): void
    {
        $poly1305 = new Poly1305();
        $key = random_bytes(32);
        $this->assertFalse($poly1305->verify('test', random_bytes(10), $key));
    }
} 