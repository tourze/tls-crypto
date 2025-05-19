<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Mac;

use Tourze\TLSCrypto\Contract\MacInterface;
use Tourze\TLSCrypto\Exception\MacException;

/**
 * Poly1305消息认证码实现
 * 使用原生PHP实现的标准Poly1305算法
 */
class Poly1305 implements MacInterface
{
    /**
     * 固定密钥长度（字节）
     */
    private const KEY_LENGTH = 32;

    /**
     * 获取MAC算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'poly1305';
    }

    /**
     * 获取MAC输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int
    {
        return 16; // Poly1305标签长度固定为16字节（128位）
    }

    /**
     * 计算消息认证码
     *
     * @param string $data 要计算MAC的数据
     * @param string $key 密钥（必须是32字节）
     * @return string MAC值
     * @throws MacException 如果计算MAC失败
     */
    public function compute(string $data, string $key): string
    {
        // 验证密钥长度
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new MacException('Poly1305密钥长度必须是32字节');
        }

        try {
            // 使用GMP扩展处理大整数
            if (extension_loaded('gmp')) {
                return $this->computeWithGMP($data, $key);
            }

            // 使用符合RFC8439的纯PHP实现
            return $this->computePurePhp($data, $key);
        } catch (\Throwable $e) {
            throw new MacException('Poly1305计算失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 使用GMP扩展计算Poly1305 MAC
     *
     * @param string $data 数据
     * @param string $key 密钥
     * @return string MAC值
     */
    private function computeWithGMP(string $data, string $key): string
    {
        // 分离密钥的两部分
        $r = substr($key, 0, 16);
        $s = substr($key, 16, 16);
        
        // 将r转换为小端序的整数格式并应用clamp
        $r_int = $this->unpackLittleEndian($r);
        // clamp r
        $r_int[0] = $r_int[0] & 0x0fffffff;
        $r_int[1] = $r_int[1] & 0x0ffffffc;
        $r_int[2] = $r_int[2] & 0x0ffffffc;
        $r_int[3] = $r_int[3] & 0x0ffffffc;
        
        // 将s转换为小端序的整数
        $s_int = $this->unpackLittleEndian($s);
        
        // 转换为GMP对象
        $r_gmp = \gmp_init(0);
        for ($i = 0; $i < 4; $i++) {
            $r_gmp = \gmp_add($r_gmp, \gmp_mul(\gmp_init($r_int[$i]), \gmp_pow(2, $i * 32)));
        }
        
        $s_gmp = \gmp_init(0);
        for ($i = 0; $i < 4; $i++) {
            $s_gmp = \gmp_add($s_gmp, \gmp_mul(\gmp_init($s_int[$i]), \gmp_pow(2, $i * 32)));
        }
        
        // Poly1305素数: 2^130 - 5
        $p = \gmp_sub(\gmp_pow(2, 130), 5);
        
        // 初始化累加器
        $h_gmp = \gmp_init(0);
        
        // 分块处理消息
        $len = strlen($data);
        for ($i = 0; $i < $len; $i += 16) {
            // 获取块并填充
            $chunk = substr($data, $i, min(16, $len - $i));
            if (strlen($chunk) < 16) {
                $chunk = str_pad($chunk, 16, "\0");
            }
            
            // 将块转换为整数并添加高位1
            $chunk_int = $this->unpackLittleEndian($chunk);
            $n_gmp = \gmp_init(0);
            for ($j = 0; $j < 4; $j++) {
                $n_gmp = \gmp_add($n_gmp, \gmp_mul(\gmp_init($chunk_int[$j]), \gmp_pow(2, $j * 32)));
            }
            
            if (strlen($chunk) < 16) {
                $n_gmp = \gmp_add($n_gmp, \gmp_mul(\gmp_init(1), \gmp_pow(2, strlen($chunk) * 8)));
            } else {
                $n_gmp = \gmp_add($n_gmp, \gmp_mul(\gmp_init(1), \gmp_pow(2, 128)));
            }
            
            // h = (h + n) * r mod p
            $h_gmp = \gmp_add($h_gmp, $n_gmp);
            $h_gmp = \gmp_mod(\gmp_mul($h_gmp, $r_gmp), $p);
        }
        
        // 添加s
        $h_gmp = \gmp_add($h_gmp, $s_gmp);
        
        // 将GMP对象转换为小端序的16字节MAC
        $h_hex = \gmp_strval($h_gmp, 16);
        $h_hex = str_pad($h_hex, 32, '0', STR_PAD_LEFT);
        
        $mac = '';
        for ($i = 0; $i < 16; $i++) {
            $mac .= chr(hexdec(substr($h_hex, 30 - $i * 2, 2)));
        }
        
        return $mac;
    }
    
    /**
     * 使用纯PHP实现计算Poly1305 MAC
     *
     * 该实现避免超出PHP整数范围的大数计算
     *
     * @param string $data 数据
     * @param string $key 密钥
     * @return string MAC值
     */
    private function computePurePhp(string $data, string $key): string
    {
        // 分离r和s
        $r = substr($key, 0, 16);
        $s = substr($key, 16, 16);
        
        // 获取r和s的字节数组（uint32数组）
        $r_uint = $this->unpackLittleEndian($r);
        $s_uint = $this->unpackLittleEndian($s);
        
        // 应用clamp到r
        $r_uint[0] &= 0x0fffffff;
        $r_uint[1] &= 0x0ffffffc;
        $r_uint[2] &= 0x0ffffffc;
        $r_uint[3] &= 0x0ffffffc;
        
        // 初始化累加器
        $h_uint = [0, 0, 0, 0, 0];
        
        // 块处理
        $len = strlen($data);
        for ($i = 0; $i < $len; $i += 16) {
            $block = substr($data, $i, min(16, $len - $i));
            
            // 处理最后一个块的填充
            if (strlen($block) < 16) {
                $block = str_pad($block, 16, "\0");
                $n_uint = $this->unpackLittleEndian($block);
                // 添加一个高位1在消息末尾
                $msb_pos = strlen($block) - strlen(rtrim($block, "\0"));
                if ($msb_pos < 16) {
                    // 确定在哪个32位字中设置位
                    $word_idx = intdiv($msb_pos, 4);
                    $bit_idx = ($msb_pos % 4) * 8;
                    $n_uint[$word_idx] |= 1 << $bit_idx;
                }
            } else {
                $n_uint = $this->unpackLittleEndian($block);
                // 对于完整块，添加额外的字节和高位1
                $n_uint[] = 1;
            }
            
            // 将n加到h
            $this->addUnits($h_uint, $n_uint);
            
            // 计算h * r
            $this->multiplyAndReduce($h_uint, $r_uint);
        }
        
        // 添加s到h
        $this->addUnits($h_uint, $s_uint);
        
        // 打包结果
        $mac = '';
        for ($i = 0; $i < 4; $i++) {
            $mac .= pack('V', $h_uint[$i]);
        }
        
        return $mac;
    }
    
    /**
     * 将字符串解包为小端序的uint32数组
     *
     * @param string $bytes 输入字节
     * @return array 返回uint32数组
     */
    private function unpackLittleEndian(string $bytes): array
    {
        $result = [];
        $len = strlen($bytes);
        
        // 每4个字节一组，解析为一个32位整数
        for ($i = 0; $i < $len; $i += 4) {
            if ($i + 4 <= $len) {
                $chunk = substr($bytes, $i, 4);
                $val = ord($chunk[0]) | (ord($chunk[1]) << 8) | (ord($chunk[2]) << 16) | (ord($chunk[3]) << 24);
                $result[] = $val;
            } else {
                // 处理不足4字节的尾部
                $val = 0;
                for ($j = 0; $j < $len - $i; $j++) {
                    $val |= ord($bytes[$i + $j]) << ($j * 8);
                }
                $result[] = $val;
            }
        }
        
        return $result;
    }
    
    /**
     * 将两个uint32数组相加，结果存储在第一个数组中
     * 
     * @param array &$a 第一个数组，也是结果存储位置
     * @param array $b 第二个数组
     */
    private function addUnits(array &$a, array $b): void
    {
        $carry = 0;
        $a_len = count($a);
        $b_len = count($b);
        $len = max($a_len, $b_len);
        
        // 确保$a数组有足够的长度
        while (count($a) < $len) {
            $a[] = 0;
        }
        
        // 逐位相加，处理进位
        for ($i = 0; $i < $len; $i++) {
            $a_val = $i < $a_len ? $a[$i] : 0;
            $b_val = $i < $b_len ? $b[$i] : 0;
            
            // 计算和，处理32位溢出
            $sum = $a_val + $b_val + $carry;
            $a[$i] = $sum & 0xffffffff; // 保留低32位
            $carry = ($sum >> 32) & 0x1; // 获取进位
        }
        
        // 如果还有进位，则添加到数组末尾
        if ($carry > 0) {
            $a[] = $carry;
        }
    }
    
    /**
     * 将h乘以r并模p，结果存储在h中
     * 该实现避免超出PHP整数范围
     * 
     * @param array &$h 累加器
     * @param array $r r值
     */
    private function multiplyAndReduce(array &$h, array $r): void
    {
        // 用于存储中间结果
        $result = [0, 0, 0, 0, 0];
        
        // 通过分解乘法为更小的部分来避免溢出
        for ($i = 0; $i < 4; $i++) {
            $carry = 0;
            for ($j = 0; $j < 4; $j++) {
                // 拆分32位乘法为较小的部分
                $low16_h = $h[$i] & 0xffff;
                $high16_h = ($h[$i] >> 16) & 0xffff;
                $low16_r = $r[$j] & 0xffff;
                $high16_r = ($r[$j] >> 16) & 0xffff;
                
                // 实现32位乘法，避免PHP整数溢出
                $prod1 = $low16_h * $low16_r;
                $prod2 = $low16_h * $high16_r;
                $prod3 = $high16_h * $low16_r;
                $prod4 = $high16_h * $high16_r;
                
                $pos = $i + $j;
                
                // 将乘积的各个部分加到适当的位置
                $sum = $result[$pos] + ($prod1 & 0xffffffff) + $carry;
                $result[$pos] = $sum & 0xffffffff;
                $carry = ($sum >> 32) & 0xffffffff;
                
                $sum = $result[$pos + 1] + ($prod2 << 16) + ($prod3 << 16) + $prod4 + $carry;
                $result[$pos + 1] = $sum & 0xffffffff;
                $carry = ($sum >> 32) & 0xffffffff;
                
                if ($carry > 0 && $pos + 2 < count($result)) {
                    $result[$pos + 2] += $carry;
                    $carry = 0;
                }
            }
        }
        
        // 模P约简操作 (P = 2^130 - 5)
        // 我们知道2^130 = 5 mod P，所以我们只需要将高位乘以5并与低位相加
        if ($result[4] > 0) {
            $carry = $result[4] * 5;
            $result[0] += $carry & 0xffffffff;
            $carry = $carry >> 32;
            
            if ($carry > 0) {
                $result[1] += $carry;
            }
        }
        
        // 更新h值
        for ($i = 0; $i < 5; $i++) {
            $h[$i] = $result[$i];
        }
    }

    /**
     * 验证消息认证码
     *
     * @param string $data 原始数据
     * @param string $mac 消息认证码
     * @param string $key 密钥
     * @return bool MAC是否有效
     */
    public function verify(string $data, string $mac, string $key): bool
    {
        // 验证MAC长度
        if (strlen($mac) !== $this->getOutputLength()) {
            return false;
        }

        // 验证密钥长度
        if (strlen($key) !== self::KEY_LENGTH) {
            return false;
        }

        try {
            $computed = $this->compute($data, $key);
            return hash_equals($computed, $mac);
        } catch (\Throwable $e) {
            return false;
        }
    }
}
