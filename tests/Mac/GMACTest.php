<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Mac;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\MacException;
use Tourze\TLSCrypto\Mac\GMAC;

class GMACTest extends TestCase
{
    public function testGetName(): void
    {
        $gmac128 = new GMAC(128);
        $this->assertEquals('gmac-128', $gmac128->getName());

        $gmac192 = new GMAC(192);
        $this->assertEquals('gmac-192', $gmac192->getName());

        $gmac256 = new GMAC(256);
        $this->assertEquals('gmac-256', $gmac256->getName());
    }

    public function testGetOutputLength(): void
    {
        $gmac = new GMAC();
        $this->assertEquals(16, $gmac->getOutputLength());
    }

    public function provideKeySizes(): array
    {
        return [
            [128],
            [192],
            [256],
        ];
    }

    /**
     * @dataProvider provideKeySizes
     */
    public function testComputeAndVerify(int $keySize): void
    {
        $gmac = new GMAC($keySize);
        $key = random_bytes($keySize / 8);
        $data = 'This is the data to authenticate with GMAC.';

        $computedMacWithIv = $gmac->compute($data, $key);
        $this->assertEquals(12 + 16, strlen($computedMacWithIv)); // IV (12) + Tag (16)

        $this->assertTrue($gmac->verify($data, $computedMacWithIv, $key));
    }

    /**
     * @dataProvider provideKeySizes
     */
    public function testVerifyWithIncorrectMac(int $keySize): void
    {
        $gmac = new GMAC($keySize);
        $key = random_bytes($keySize / 8);
        $data = 'Some data.';

        $correctMacWithIv = $gmac->compute($data, $key);
        $iv = substr($correctMacWithIv, 0, 12);
        $incorrectTag = random_bytes(16);
        $incorrectMacWithIv = $iv . $incorrectTag;

        $this->assertFalse($gmac->verify($data, $incorrectMacWithIv, $key));
    }

    /**
     * @dataProvider provideKeySizes
     */
    public function testVerifyWithIncorrectKey(int $keySize): void
    {
        $gmac = new GMAC($keySize);
        $key1 = random_bytes($keySize / 8);
        $key2 = random_bytes($keySize / 8);
        $data = 'Some important data.';

        $macWithIv = $gmac->compute($data, $key1);
        $this->assertFalse($gmac->verify($data, $macWithIv, $key2));
    }

    /**
     * @dataProvider provideKeySizes
     */
    public function testVerifyWithCorruptedData(int $keySize): void
    {
        $gmac = new GMAC($keySize);
        $key = random_bytes($keySize / 8);
        $data = 'Original Data String';
        $corruptedData = 'Corrupted Data String';

        $macWithIv = $gmac->compute($data, $key);
        $this->assertFalse($gmac->verify($corruptedData, $macWithIv, $key));
    }

    public function testComputeWithInvalidKeyLength(): void
    {
        $this->expectException(MacException::class);
        $this->expectExceptionMessage('密钥长度不匹配，需要32字节'); // For default 256-bit GMAC

        $gmac = new GMAC(256);
        $key = random_bytes(16); // Invalid length
        $gmac->compute('testdata', $key);
    }

    public function testVerifyWithInvalidMacLength(): void
    {
        $gmac = new GMAC(256);
        $key = random_bytes(32);
        $this->assertFalse($gmac->verify('test', random_bytes(10), $key));
    }

    public function testVerifyWithInvalidKeyLengthInVerify(): void
    {
        $gmac = new GMAC(256);
        $key = random_bytes(32);
        $data = 'test data';
        $computedMac = $gmac->compute($data, $key);

        $invalidKey = random_bytes(16);
        $this->assertFalse($gmac->verify($data, $computedMac, $invalidKey));
    }

    public function testConstructorWithInvalidKeySize(): void
    {
        $this->expectException(MacException::class);
        $this->expectExceptionMessage('无效的GMAC密钥大小，有效值为128、192或256位');
        new GMAC(64);
    }
} 