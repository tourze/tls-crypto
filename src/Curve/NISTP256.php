<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Curve;

use Tourze\TLSCrypto\Contract\CurveInterface;
use Tourze\TLSCrypto\Exception\CurveException;

/**
 * NIST P-256 椭圆曲线实现
 */
class NISTP256 implements CurveInterface
{
    /**
     * OpenSSL中的曲线名称
     */
    private const CURVE_NAME = 'prime256v1'; // NIST P-256的OpenSSL名称
    
    /**
     * 密钥大小（位）
     */
    private const KEY_SIZE = 256;
    
    /**
     * 获取曲线名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'nistp256';
    }

    /**
     * 获取曲线的密钥大小（位）
     *
     * @return int
     */
    public function getKeySize(): int
    {
        return self::KEY_SIZE;
    }

    /**
     * 生成密钥对
     *
     * @return array 包含私钥和公钥的数组
     * @throws CurveException 如果生成密钥对失败
     */
    public function generateKeyPair(): array
    {
        // 检查OpenSSL扩展是否加载
        if (!extension_loaded('openssl')) {
            throw new CurveException('OpenSSL扩展未加载');
        }
        
        // 创建EC密钥对
        $config = [
            'curve_name' => self::CURVE_NAME,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ];
        
        $res = openssl_pkey_new($config);
        if ($res === false) {
            throw new CurveException('EC密钥对生成失败: ' . openssl_error_string());
        }
        
        // 导出私钥（PEM格式）
        if (!openssl_pkey_export($res, $privateKeyPem)) {
            throw new CurveException('EC私钥导出失败: ' . openssl_error_string());
        }
        
        // 导出公钥（PEM格式）
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new CurveException('获取EC密钥详情失败: ' . openssl_error_string());
        }
        
        $publicKeyPem = $details['key'];
        
        return [
            'privateKey' => $privateKeyPem,
            'publicKey' => $publicKeyPem,
        ];
    }

    /**
     * 从私钥生成公钥
     *
     * @param string $privateKey 私钥（PEM格式）
     * @return string 公钥（PEM格式）
     * @throws CurveException 如果生成公钥失败
     */
    public function derivePublicKey(string $privateKey): string
    {
        // 检查OpenSSL扩展是否加载
        if (!extension_loaded('openssl')) {
            throw new CurveException('OpenSSL扩展未加载');
        }
        
        // 加载私钥
        $res = openssl_pkey_get_private($privateKey);
        if ($res === false) {
            throw new CurveException('加载EC私钥失败: ' . openssl_error_string());
        }
        
        // 获取密钥详情
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new CurveException('获取EC密钥详情失败: ' . openssl_error_string());
        }
        
        // 检查密钥类型
        if ($details['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new CurveException('提供的密钥不是EC密钥');
        }
        
        return $details['key'];
    }
}
