<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Mac;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Hash\SHA256;
use Tourze\TLSCrypto\Hash\SHA384;
use Tourze\TLSCrypto\Hash\SHA512;
use Tourze\TLSCrypto\Mac\HMAC;

/**
 * HMAC测试类
 */
class HMACTest extends TestCase
{
    /**
     * 测试HMAC-SHA256
     */
    public function testHmacSha256(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        // 测试获取名称
        $this->assertEquals('hmac-sha256', $hmac->getName());

        // 测试获取输出长度
        $this->assertEquals($hash->getOutputLength(), $hmac->getOutputLength());

        // 测试计算和验证HMAC
        $data = 'Test Message';
        $key = 'Secret Key';

        $expected = hash_hmac('sha256', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $computedMac, $key));
        $this->assertFalse($hmac->verify($data, $computedMac, 'Wrong Key'));
    }

    /**
     * 测试HMAC-SHA384
     */
    public function testHmacSha384(): void
    {
        $hash = new SHA384();
        $hmac = new HMAC($hash);

        // 测试获取名称
        $this->assertEquals('hmac-sha384', $hmac->getName());

        // 测试获取输出长度
        $this->assertEquals($hash->getOutputLength(), $hmac->getOutputLength());

        // 测试计算和验证HMAC
        $data = 'Test Message';
        $key = 'Secret Key';

        $expected = hash_hmac('sha384', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $computedMac, $key));
        $this->assertFalse($hmac->verify($data, $computedMac, 'Wrong Key'));
    }

    /**
     * 测试HMAC-SHA512
     */
    public function testHmacSha512(): void
    {
        $hash = new SHA512();
        $hmac = new HMAC($hash);

        // 测试获取名称
        $this->assertEquals('hmac-sha512', $hmac->getName());

        // 测试获取输出长度
        $this->assertEquals($hash->getOutputLength(), $hmac->getOutputLength());

        // 测试计算和验证HMAC
        $data = 'Test Message';
        $key = 'Secret Key';

        $expected = hash_hmac('sha512', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $computedMac, $key));
        $this->assertFalse($hmac->verify($data, $computedMac, 'Wrong Key'));
    }

    /**
     * 测试空数据的HMAC计算
     */
    public function testEmptyDataHmac(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        $data = '';
        $key = 'Secret Key';

        $expected = hash_hmac('sha256', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
    }

    /**
     * 测试不同长度密钥的HMAC计算
     */
    public function testDifferentKeyLengths(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        $data = 'Test Message';
        $keys = [
            'Short',
            'Medium Length Key',
            str_repeat('Long Key ', 10),
        ];

        foreach ($keys as $key) {
            $expected = hash_hmac('sha256', $data, $key, true);
            $computedMac = $hmac->compute($data, $key);

            $this->assertEquals($expected, $computedMac);
            $this->assertTrue($hmac->verify($data, $computedMac, $key));
        }
    }
}
