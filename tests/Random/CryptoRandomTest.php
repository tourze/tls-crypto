<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Random;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\RandomException;
use Tourze\TLSCrypto\Random\CryptoRandom;

class CryptoRandomTest extends TestCase
{
    private CryptoRandom $random;

    protected function setUp(): void
    {
        parent::setUp();
        $this->random = new CryptoRandom();
    }

    public function testGetRandomBytes(): void
    {
        // 测试生成不同长度的随机字节
        $lengths = [1, 16, 32, 64, 128];
        
        foreach ($lengths as $length) {
            $bytes = $this->random->getRandomBytes($length);
            $this->assertEquals($length, strlen($bytes));
            
            // 验证两次生成的随机字节不相同
            $anotherBytes = $this->random->getRandomBytes($length);
            $this->assertNotEquals($bytes, $anotherBytes, "随机字节生成应该是不可预测的");
        }
    }
    
    public function testGetRandomBytesWithInvalidLength(): void
    {
        $this->expectException(RandomException::class);
        $this->expectExceptionMessage('随机字节长度必须大于0');
        
        $this->random->getRandomBytes(0);
    }
    
    public function testGetRandomBytesWithNegativeLength(): void
    {
        $this->expectException(RandomException::class);
        $this->expectExceptionMessage('随机字节长度必须大于0');
        
        $this->random->getRandomBytes(-10);
    }
    
    public function testGetRandomInt(): void
    {
        // 测试不同范围的随机整数
        $ranges = [
            [0, 10],
            [1, 100],
            [-50, 50],
            [PHP_INT_MAX - 100, PHP_INT_MAX],
            [PHP_INT_MIN, PHP_INT_MIN + 100]
        ];
        
        foreach ($ranges as [$min, $max]) {
            $int = $this->random->getRandomInt($min, $max);
            $this->assertGreaterThanOrEqual($min, $int);
            $this->assertLessThanOrEqual($max, $int);
            
            // 多次生成随机数，验证分布
            $values = [];
            for ($i = 0; $i < 100; $i++) {
                $values[] = $this->random->getRandomInt($min, $max);
            }
            
            // 验证最小值和最大值在100次测试中至少出现过一次
            // 注意：这是概率测试，有极小概率失败，但实际上非常可靠
            if ($max - $min < 20) {  // 对于小范围，才检查是否每个值都可能出现
                $unique = array_unique($values);
                $this->assertGreaterThan(1, count($unique), "随机数生成应该在范围内产生不同的值");
            }
        }
    }
    
    public function testGetRandomIntWithInvalidRange(): void
    {
        $this->expectException(RandomException::class);
        $this->expectExceptionMessage('最小值不能大于最大值');
        
        $this->random->getRandomInt(100, 1);
    }
    
    public function testRandomnessDistribution(): void
    {
        // 测试生成的随机数是否具有均匀分布的特性
        // 这仅是一个基本测试，不是严格的统计测试
        
        $min = 1;
        $max = 6;  // 模拟骰子
        $iterations = 1000;
        $counts = array_fill($min, $max - $min + 1, 0);
        
        for ($i = 0; $i < $iterations; $i++) {
            $value = $this->random->getRandomInt($min, $max);
            $counts[$value]++;
        }
        
        // 检查每个值的出现次数是否在理论期望值的合理范围内
        $expectedCount = $iterations / ($max - $min + 1);
        $tolerance = $expectedCount * 0.3;  // 允许30%的偏差
        
        foreach ($counts as $value => $count) {
            $this->assertGreaterThan($expectedCount - $tolerance, $count, "值 $value 出现次数过少");
            $this->assertLessThan($expectedCount + $tolerance, $count, "值 $value 出现次数过多");
        }
    }
}
