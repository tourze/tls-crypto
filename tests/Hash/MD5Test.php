<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Hash;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\CryptoFactory;
use Tourze\TLSCrypto\Hash\MD5;

/**
 * MD5哈希函数测试
 */
class MD5Test extends TestCase
{
    /**
     * 测试获取哈希算法名称
     */
    public function testGetName(): void
    {
        $md5 = new MD5();
        $this->assertEquals('md5', $md5->getName());
    }

    /**
     * 测试获取哈希输出长度
     */
    public function testGetOutputLength(): void
    {
        $md5 = new MD5();
        $this->assertEquals(16, $md5->getOutputLength());
    }

    /**
     * 测试获取哈希块大小
     */
    public function testGetBlockSize(): void
    {
        $md5 = new MD5();
        $this->assertEquals(64, $md5->getBlockSize());
    }

    /**
     * 测试计算数据的哈希值
     */
    public function testHash(): void
    {
        $md5 = new MD5();
        $data = 'test data';
        $hash = $md5->hash($data);
        
        // 验证哈希长度正确
        $this->assertEquals(16, strlen($hash));
        
        // 验证哈希值正确
        $expectedHash = hash('md5', $data, true);
        $this->assertEquals($expectedHash, $hash);
    }

    /**
     * 测试使用哈希上下文计算哈希值
     */
    public function testHashWithContext(): void
    {
        $md5 = new MD5();
        $data1 = 'part1';
        $data2 = 'part2';

        // 直接计算整个数据的哈希值
        $expectedHash = $md5->hash($data1 . $data2);

        // 使用上下文分段计算哈希值
        $context = $md5->createContext();
        $md5->updateContext($context, $data1);
        $md5->updateContext($context, $data2);
        $actualHash = $md5->finalizeContext($context);

        $this->assertEquals($expectedHash, $actualHash);
    }

    /**
     * 测试通过工厂类创建哈希函数
     */
    public function testCreateThroughFactory(): void
    {
        $md5 = CryptoFactory::createHash('md5');
        $this->assertInstanceOf(MD5::class, $md5);
        $this->assertEquals('md5', $md5->getName());
    }

    /**
     * 测试空字符串的哈希值
     */
    public function testEmptyStringHash(): void
    {
        $md5 = new MD5();
        $hash = $md5->hash('');
        $expectedHash = hash('md5', '', true);
        $this->assertEquals($expectedHash, $hash);
    }

    /**
     * 测试长数据的哈希值
     */
    public function testLongDataHash(): void
    {
        $md5 = new MD5();
        $data = str_repeat('a', 1000000); // 100万个'a'

        $hash = $md5->hash($data);
        $expectedHash = hash('md5', $data, true);
        $this->assertEquals($expectedHash, $hash);
    }
}
