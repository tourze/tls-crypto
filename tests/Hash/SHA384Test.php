<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Hash;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Hash\SHA384;

/**
 * SHA384测试类
 */
class SHA384Test extends TestCase
{
    private SHA384 $hash;

    /**
     * 测试获取哈希算法名称
     */
    public function testGetName(): void
    {
        $this->assertEquals('sha384', $this->hash->getName());
    }

    /**
     * 测试获取哈希输出长度
     */
    public function testGetOutputLength(): void
    {
        $this->assertEquals(48, $this->hash->getOutputLength()); // 384位 = 48字节
    }

    /**
     * 测试获取哈希块大小
     */
    public function testGetBlockSize(): void
    {
        $this->assertEquals(128, $this->hash->getBlockSize()); // SHA-384块大小为128字节
    }

    /**
     * 测试哈希计算
     */
    public function testHash(): void
    {
        $data = 'Hello, World!';
        $expected = hash('sha384', $data, true);

        $result = $this->hash->hash($data);

        $this->assertEquals($expected, $result);
        $this->assertEquals(48, strlen($result));
    }

    /**
     * 测试空字符串的哈希值
     */
    public function testHashEmptyString(): void
    {
        $expected = hash('sha384', '', true);
        $result = $this->hash->hash('');

        $this->assertEquals($expected, $result);
    }

    /**
     * 测试增量哈希计算
     */
    public function testIncrementalHash(): void
    {
        $part1 = 'Hello, ';
        $part2 = 'World!';
        $fullData = $part1 . $part2;

        // 直接计算完整数据的哈希
        $expectedHash = $this->hash->hash($fullData);

        // 使用增量方式计算哈希
        $context = $this->hash->createContext();
        $this->hash->updateContext($context, $part1);
        $this->hash->updateContext($context, $part2);
        $incrementalHash = $this->hash->finalizeContext($context);

        $this->assertEquals($expectedHash, $incrementalHash);
    }

    protected function setUp(): void
    {
        $this->hash = new SHA384();
    }
}
