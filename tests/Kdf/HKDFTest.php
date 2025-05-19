<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Kdf;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\KdfException;
use Tourze\TLSCrypto\Hash\SHA256;
use Tourze\TLSCrypto\Hash\SHA384;
use Tourze\TLSCrypto\Hash\SHA512;
use Tourze\TLSCrypto\Kdf\HKDF;

/**
 * HKDF测试类
 */
class HKDFTest extends TestCase
{
    /**
     * 测试HKDF-SHA256
     */
    public function testHkdfSha256(): void
    {
        $hash = new SHA256();
        $hkdf = new HKDF($hash);

        // 测试获取名称
        $this->assertEquals('hkdf-sha256', $hkdf->getName());

        // 测试HKDF密钥导出
        $ikm = 'input key material';
        $salt = 'salt value';
        $info = 'context information';
        $length = 32;

        $derivedKey1 = $hkdf->derive($ikm, $salt, $info, $length);
        $derivedKey2 = $hkdf->derive($ikm, $salt, $info, $length);

        // 相同输入应产生相同输出
        $this->assertEquals($derivedKey1, $derivedKey2);

        // 检查输出长度
        $this->assertEquals($length, strlen($derivedKey1));

        // 不同输入应产生不同输出
        $derivedKey3 = $hkdf->derive($ikm, $salt, 'different info', $length);
        $this->assertNotEquals($derivedKey1, $derivedKey3);

        $derivedKey4 = $hkdf->derive($ikm, 'different salt', $info, $length);
        $this->assertNotEquals($derivedKey1, $derivedKey4);

        $derivedKey5 = $hkdf->derive('different ikm', $salt, $info, $length);
        $this->assertNotEquals($derivedKey1, $derivedKey5);
    }

    /**
     * 测试HKDF-SHA384
     */
    public function testHkdfSha384(): void
    {
        $hash = new SHA384();
        $hkdf = new HKDF($hash);

        // 测试获取名称
        $this->assertEquals('hkdf-sha384', $hkdf->getName());

        // 测试HKDF密钥导出
        $ikm = 'input key material';
        $salt = 'salt value';
        $info = 'context information';
        $length = 48;

        $derivedKey = $hkdf->derive($ikm, $salt, $info, $length);

        // 检查输出长度
        $this->assertEquals($length, strlen($derivedKey));
    }

    /**
     * 测试HKDF-SHA512
     */
    public function testHkdfSha512(): void
    {
        $hash = new SHA512();
        $hkdf = new HKDF($hash);

        // 测试获取名称
        $this->assertEquals('hkdf-sha512', $hkdf->getName());

        // 测试HKDF密钥导出
        $ikm = 'input key material';
        $salt = 'salt value';
        $info = 'context information';
        $length = 64;

        $derivedKey = $hkdf->derive($ikm, $salt, $info, $length);

        // 检查输出长度
        $this->assertEquals($length, strlen($derivedKey));
    }

    /**
     * 测试无盐值的HKDF
     */
    public function testHkdfWithoutSalt(): void
    {
        $hash = new SHA256();
        $hkdf = new HKDF($hash);

        $ikm = 'input key material';
        $salt = '';
        $info = 'context information';
        $length = 32;

        $derivedKey = $hkdf->derive($ikm, $salt, $info, $length);

        // 检查输出长度
        $this->assertEquals($length, strlen($derivedKey));
    }

    /**
     * 测试无上下文信息的HKDF
     */
    public function testHkdfWithoutInfo(): void
    {
        $hash = new SHA256();
        $hkdf = new HKDF($hash);

        $ikm = 'input key material';
        $salt = 'salt value';
        $info = '';
        $length = 32;

        $derivedKey = $hkdf->derive($ikm, $salt, $info, $length);

        // 检查输出长度
        $this->assertEquals($length, strlen($derivedKey));
    }

    /**
     * 测试长度为0的HKDF导出
     */
    public function testHkdfWithZeroLength(): void
    {
        $hash = new SHA256();
        $hkdf = new HKDF($hash);

        $ikm = 'input key material';
        $salt = 'salt value';
        $info = 'context information';
        $length = 0;

        $this->expectException(KdfException::class);
        $hkdf->derive($ikm, $salt, $info, $length);
    }

    /**
     * 测试与RFC 5869示例向量的一致性
     * 来源: https://tools.ietf.org/html/rfc5869#appendix-A.1
     */
    public function testRfc5869TestVector1(): void
    {
        // 这是RFC 5869中测试向量1的简化版本
        $hash = new SHA256();
        $hkdf = new HKDF($hash);

        $ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $salt = hex2bin('000102030405060708090a0b0c');
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        $length = 42;

        $expectedOutput = hex2bin(
            '3cb25f25faacd57a90434f64d0362f2a' .
            '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' .
            '34007208d5b887185865'
        );

        $derivedKey = $hkdf->derive($ikm, $salt, $info, $length);

        $this->assertEquals($expectedOutput, $derivedKey);
    }
}
