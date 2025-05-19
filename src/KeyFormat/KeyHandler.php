<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\KeyFormat;

use Tourze\TLSCrypto\Exception\KeyFormatException;

/**
 * 密钥处理类
 * 
 * 用于处理各种格式的公钥和私钥数据
 */
class KeyHandler
{
    /**
     * @var PemDerFormat
     */
    private PemDerFormat $pemDerFormat;

    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->pemDerFormat = new PemDerFormat();
    }

    /**
     * 验证RSA私钥
     *
     * @param string $keyPem 私钥PEM数据
     * @return bool 是否有效
     */
    public function isValidRsaPrivateKey(string $keyPem): bool
    {
        if (!$this->pemDerFormat->isValidPem($keyPem)) {
            return false;
        }

        $privateKey = openssl_pkey_get_private($keyPem);
        if ($privateKey === false) {
            return false;
        }

        $details = openssl_pkey_get_details($privateKey);
        return $details !== false && isset($details['key']) && $details['type'] === OPENSSL_KEYTYPE_RSA;
    }

    /**
     * 验证EC私钥
     *
     * @param string $keyPem 私钥PEM数据
     * @return bool 是否有效
     */
    public function isValidEcPrivateKey(string $keyPem): bool
    {
        if (!$this->pemDerFormat->isValidPem($keyPem)) {
            return false;
        }

        $privateKey = openssl_pkey_get_private($keyPem);
        if ($privateKey === false) {
            return false;
        }

        $details = openssl_pkey_get_details($privateKey);
        return $details !== false && isset($details['key']) && $details['type'] === OPENSSL_KEYTYPE_EC;
    }

    /**
     * 验证公钥
     *
     * @param string $keyPem 公钥PEM数据
     * @return bool 是否有效
     */
    public function isValidPublicKey(string $keyPem): bool
    {
        if (!$this->pemDerFormat->isValidPem($keyPem)) {
            return false;
        }

        $publicKey = openssl_pkey_get_public($keyPem);
        return $publicKey !== false;
    }

    /**
     * 从私钥中提取公钥
     *
     * @param string $privateKeyPem 私钥PEM数据
     * @return string 公钥PEM数据
     * @throws KeyFormatException 如果提取失败
     */
    public function extractPublicKey(string $privateKeyPem): string
    {
        if (!$this->pemDerFormat->isValidPem($privateKeyPem)) {
            throw new KeyFormatException('无效的私钥PEM格式');
        }

        $privateKey = openssl_pkey_get_private($privateKeyPem);
        if ($privateKey === false) {
            throw new KeyFormatException('读取私钥失败: ' . openssl_error_string());
        }

        $keyDetails = openssl_pkey_get_details($privateKey);
        if ($keyDetails === false || !isset($keyDetails['key'])) {
            throw new KeyFormatException('获取密钥详情失败: ' . openssl_error_string());
        }

        return $keyDetails['key'];
    }

    /**
     * 获取RSA密钥信息
     *
     * @param string $keyPem 公钥或私钥PEM数据
     * @return array 密钥信息
     * @throws KeyFormatException 如果获取失败
     */
    public function getRsaKeyInfo(string $keyPem): array
    {
        if (!$this->pemDerFormat->isValidPem($keyPem)) {
            throw new KeyFormatException('无效的PEM格式');
        }

        // 尝试作为公钥或私钥解析
        $key = openssl_pkey_get_public($keyPem) ?: openssl_pkey_get_private($keyPem);
        if ($key === false) {
            throw new KeyFormatException('无效的RSA密钥: ' . openssl_error_string());
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['rsa']) || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new KeyFormatException('不是有效的RSA密钥或获取密钥详情失败');
        }

        // 返回RSA关键参数
        return [
            'bits' => $details['bits'],
            'n' => bin2hex($details['rsa']['n']), // 模数
            'e' => bin2hex($details['rsa']['e']), // 公开指数
            'isPrivate' => isset($details['rsa']['d']), // 如果有d参数则为私钥
        ];
    }

    /**
     * 获取EC密钥信息
     *
     * @param string $keyPem 公钥或私钥PEM数据
     * @return array 密钥信息
     * @throws KeyFormatException 如果获取失败
     */
    public function getEcKeyInfo(string $keyPem): array
    {
        if (!$this->pemDerFormat->isValidPem($keyPem)) {
            throw new KeyFormatException('无效的PEM格式');
        }

        // 尝试作为公钥或私钥解析
        $key = openssl_pkey_get_public($keyPem) ?: openssl_pkey_get_private($keyPem);
        if ($key === false) {
            throw new KeyFormatException('无效的EC密钥: ' . openssl_error_string());
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['ec']) || $details['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new KeyFormatException('不是有效的EC密钥或获取密钥详情失败');
        }

        // 返回EC关键参数
        return [
            'curve_name' => $details['ec']['curve_name'],
            'x' => bin2hex($details['ec']['x']),
            'y' => bin2hex($details['ec']['y']),
            'isPrivate' => isset($details['ec']['d']),
        ];
    }

    /**
     * 转换密钥格式（例如PKCS#1转PKCS#8等）
     *
     * @param string $keyPem 源密钥PEM数据
     * @param int $fromFormat 源格式
     * @param int $toFormat 目标格式
     * @return string 转换后的密钥PEM数据
     * @throws KeyFormatException 如果转换失败
     */
    public function convertKeyFormat(string $keyPem, int $fromFormat, int $toFormat): string
    {
        if (!$this->pemDerFormat->isValidPem($keyPem)) {
            throw new KeyFormatException('无效的PEM格式');
        }

        // 支持的格式常量
        $PKCS1 = 1;
        $PKCS8 = 8;

        // 验证格式类型
        if (!in_array($fromFormat, [$PKCS1, $PKCS8]) || !in_array($toFormat, [$PKCS1, $PKCS8])) {
            throw new KeyFormatException('不支持的密钥格式');
        }

        // 如果源格式和目标格式相同，直接返回
        if ($fromFormat === $toFormat) {
            return $keyPem;
        }

        // 尝试读取密钥
        $privateKey = openssl_pkey_get_private($keyPem);
        if ($privateKey === false) {
            throw new KeyFormatException('读取私钥失败: ' . openssl_error_string());
        }

        // 根据目标格式转换
        $keyData = '';
        
        if ($toFormat === $PKCS8) {
            // 转换为PKCS#8
            $configArgs = [
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ];
            if (!openssl_pkey_export($privateKey, $keyData, null, $configArgs)) {
                throw new KeyFormatException('转换为PKCS#8格式失败: ' . openssl_error_string());
            }
        } else {
            // 转换为PKCS#1 - 默认输出格式
            if (!openssl_pkey_export($privateKey, $keyData)) {
                throw new KeyFormatException('转换为PKCS#1格式失败: ' . openssl_error_string());
            }
        }

        return $keyData;
    }
} 