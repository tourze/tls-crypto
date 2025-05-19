<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Kdf;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\CryptoFactory;
use Tourze\TLSCrypto\Exception\KdfException;
use Tourze\TLSCrypto\Kdf\PBKDF2;

class PBKDF2Test extends TestCase
{
    public function testGetName(): void
    {
        $hash = CryptoFactory::createHash('sha256');
        $kdf = new PBKDF2($hash);
        $this->assertEquals('pbkdf2-sha256', $kdf->getName());
    }

    public function testDeriveWithValidInputs(): void
    {
        $hash = CryptoFactory::createHash('sha256');
        $kdf = new PBKDF2($hash, 1000); // 使用较少的迭代次数以加快测试

        $password = 'password';
        $salt = 'salt';
        $length = 32;

        $derivedKey = $kdf->derive($password, $salt, '', $length);
        $this->assertEquals($length, strlen($derivedKey));

        // 使用已知的测试向量进行验证 (RFC 6070 PBKDF2 test vectors for SHA256)
        // 这里使用一个简化的本地计算结果作为示例，实际测试中应使用标准测试向量
        if (function_exists('hash_pbkdf2')) {
            $expected = hash_pbkdf2('sha256', $password, $salt, 1000, $length, true);
            $this->assertEquals($expected, $derivedKey);
        }
    }

    public function testDeriveWithDifferentHash(): void
    {
        $hash = CryptoFactory::createHash('sha512');
        $kdf = new PBKDF2($hash, 1000);

        $password = 'password123';
        $salt = 'salty';
        $length = 64;

        $derivedKey = $kdf->derive($password, $salt, '', $length);
        $this->assertEquals($length, strlen($derivedKey));
        if (function_exists('hash_pbkdf2')) {
            $expected = hash_pbkdf2('sha512', $password, $salt, 1000, $length, true);
            $this->assertEquals($expected, $derivedKey);
        }
    }

    public function testDeriveWithDifferentOutputLength(): void
    {
        $hash = CryptoFactory::createHash('sha256');
        $kdf = new PBKDF2($hash, 1000);
        $password = 'password';
        $salt = 'salt';

        $length = 16;
        $derivedKey16 = $kdf->derive($password, $salt, '', $length);
        $this->assertEquals($length, strlen($derivedKey16));

        $length = 64;
        $derivedKey64 = $kdf->derive($password, $salt, '', $length);
        $this->assertEquals($length, strlen($derivedKey64));

        $this->assertEquals($derivedKey16, substr($derivedKey64, 0, 16));
    }

    public function testDeriveWithInvalidLength(): void
    {
        $this->expectException(KdfException::class);
        $this->expectExceptionMessage('导出的密钥长度必须大于0');

        $hash = CryptoFactory::createHash('sha256');
        $kdf = new PBKDF2($hash);
        $kdf->derive('password', 'salt', '', 0);
    }

    public function testDeriveWithEmptySalt(): void
    {
        $this->expectException(KdfException::class);
        $this->expectExceptionMessage('盐值不能为空');

        $hash = CryptoFactory::createHash('sha256');
        $kdf = new PBKDF2($hash);
        $kdf->derive('password', '', '', 32);
    }

    public function testConstructorWithInvalidIterations(): void
    {
        $this->expectException(KdfException::class);
        $this->expectExceptionMessage('迭代次数应至少为1000以确保安全性');

        $hash = CryptoFactory::createHash('sha256');
        new PBKDF2($hash, 999);
    }

    public function testPbkdf2ImplementationFallback(): void
    {
        // 这个测试依赖于 hash_pbkdf2 函数不存在的情况，这在标准测试环境中难以模拟。
        // 如果可以模拟，我们会测试手动实现是否与预期一致。
        // 这里我们假设 hash_pbkdf2 总是存在，如果它不存在，前面的测试会覆盖手动实现。
        $hash = CryptoFactory::createHash('sha256');
        $kdf = new PBKDF2($hash, 1000);

        $password = 'test_password';
        $salt = 'test_salt';
        $length = 24;

        // 手动计算一个预期值（如果 hash_pbkdf2 存在，这个测试主要保证 derive 方法的逻辑正确）
        $hashAlgo = 'sha256';
        $hashLength = $hash->getOutputLength(); // 32 for sha256
        $blockCount = ceil($length / $hashLength); // 24/32 -> 1
        $output = '';

        for ($i = 1; $i <= $blockCount; $i++) {
            $block = $u = hash_hmac(
                $hashAlgo,
                $salt . pack('N', $i),
                $password,
                true
            );
            for ($j = 1; $j < 1000; $j++) {
                $u = hash_hmac($hashAlgo, $u, $password, true);
                $block ^= $u;
            }
            $output .= $block;
        }
        $expectedManual = substr($output, 0, $length);

        $derivedKey = $kdf->derive($password, $salt, '', $length);
        $this->assertEquals($length, strlen($derivedKey));

        if (!function_exists('hash_pbkdf2')) {
            $this->assertEquals($expectedManual, $derivedKey, "Fallback implementation mismatch");
        } else {
            $expectedBuiltIn = hash_pbkdf2($hashAlgo, $password, $salt, 1000, $length, true);
            $this->assertEquals($expectedBuiltIn, $derivedKey, "Built-in function implementation mismatch");
        }
    }
}
