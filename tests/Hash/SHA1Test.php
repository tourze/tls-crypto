<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Hash;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\CryptoFactory;
use Tourze\TLSCrypto\Hash\SHA1;

/**
 * SHA-1哈希函数测试
 */
class SHA1Test extends TestCase
{
    /**
     * 测试获取哈希算法名称
     */
    public function testGetName(): void
    {
        $sha1 = new SHA1();
        $this->assertEquals('sha1', $sha1->getName());
    }

    /**
     * 测试获取哈希输出长度
     */
    public function testGetOutputLength(): void
    {
        $sha1 = new SHA1();
        $this->assertEquals(20, $sha1->getOutputLength());
    }

    /**
     * 测试获取哈希块大小
     */
    public function testGetBlockSize(): void
    {
        $sha1 = new SHA1();
        $this->assertEquals(64, $sha1->getBlockSize());
    }

    /**
     * 测试计算数据的哈希值
     */
    public function testHash(): void
    {
        $sha1 = new SHA1();
        $data = 'test data';
        $hash = $sha1->hash($data);
        
        // 验证哈希长度正确
        $this->assertEquals(20, strlen($hash));
        
        // 验证哈希值正确
        $expectedHash = hash('sha1', $data, true);
        $this->assertEquals($expectedHash, $hash);
    }

    /**
     * 测试使用哈希上下文计算哈希值
     */
    public function testHashWithContext(): void
    {
        $sha1 = new SHA1();
        $data1 = 'part1';
        $data2 = 'part2';
        
        // 直接计算整个数据的哈希值
        $expectedHash = $sha1->hash($data1 . $data2);
        
        // 使用上下文分段计算哈希值
        $context = $sha1->createContext();
        $sha1->updateContext($context, $data1);
        $sha1->updateContext($context, $data2);
        $actualHash = $sha1->finalizeContext($context);
        
        $this->assertEquals($expectedHash, $actualHash);
    }

    /**
     * 测试通过工厂类创建哈希函数
     */
    public function testCreateThroughFactory(): void
    {
        $sha1 = CryptoFactory::createHash('sha1');
        $this->assertInstanceOf(SHA1::class, $sha1);
        $this->assertEquals('sha1', $sha1->getName());
    }

    /**
     * 测试空字符串的哈希值
     */
    public function testEmptyStringHash(): void
    {
        $sha1 = new SHA1();
        $hash = $sha1->hash('');
        $expectedHash = hash('sha1', '', true);
        $this->assertEquals($expectedHash, $hash);
    }

    /**
     * 测试长数据的哈希值
     */
    public function testLongDataHash(): void
    {
        $sha1 = new SHA1();
        $data = str_repeat('a', 1000000); // 100万个'a'

        $hash = $sha1->hash($data);
        $expectedHash = hash('sha1', $data, true);
        $this->assertEquals($expectedHash, $hash);
    }
}
