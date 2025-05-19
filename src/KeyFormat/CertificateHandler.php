<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\KeyFormat;

use Tourze\TLSCrypto\Exception\KeyFormatException;

/**
 * X.509证书处理类
 */
class CertificateHandler
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
     * 从PEM格式解析X.509证书
     *
     * @param string $pemData PEM格式的证书数据
     * @return array 解析后的证书信息
     * @throws KeyFormatException 如果解析失败
     */
    public function parseCertificate(string $pemData): array
    {
        if (!$this->pemDerFormat->isValidPem($pemData)) {
            throw new KeyFormatException('无效的PEM格式证书');
        }

        // 提取证书数据
        $extracted = $this->pemDerFormat->extractFromPem($pemData);
        
        if ($extracted['type'] !== 'CERTIFICATE') {
            throw new KeyFormatException('提供的PEM数据不是证书格式');
        }

        // 使用OpenSSL解析证书
        $certData = openssl_x509_parse($pemData);
        if ($certData === false) {
            throw new KeyFormatException('解析证书失败: ' . openssl_error_string());
        }

        return $certData;
    }

    /**
     * 验证证书是否有效
     *
     * @param string $certPem 待验证的证书PEM
     * @param string|null $caPem CA证书PEM，如果为null则自验证
     * @return bool 是否有效
     * @throws KeyFormatException 如果验证过程出错
     */
    public function verifyCertificate(string $certPem, ?string $caPem = null): bool
    {
        if (!$this->pemDerFormat->isValidPem($certPem)) {
            throw new KeyFormatException('无效的证书PEM格式');
        }

        if ($caPem !== null && !$this->pemDerFormat->isValidPem($caPem)) {
            throw new KeyFormatException('无效的CA证书PEM格式');
        }

        // 如果没有提供CA证书，则进行自验证
        if ($caPem === null) {
            $result = openssl_x509_verify($certPem, openssl_pkey_get_public($certPem));
        } else {
            $result = openssl_x509_verify($certPem, openssl_pkey_get_public($caPem));
        }

        if ($result === -1) {
            throw new KeyFormatException('证书验证错误: ' . openssl_error_string());
        }

        return $result === 1;
    }

    /**
     * 提取证书的公钥
     *
     * @param string $certPem 证书PEM
     * @return string 公钥PEM
     * @throws KeyFormatException 如果提取失败
     */
    public function extractPublicKey(string $certPem): string
    {
        if (!$this->pemDerFormat->isValidPem($certPem)) {
            throw new KeyFormatException('无效的证书PEM格式');
        }

        $certResource = openssl_x509_read($certPem);
        if ($certResource === false) {
            throw new KeyFormatException('读取证书失败: ' . openssl_error_string());
        }

        $pubKey = openssl_pkey_get_public($certResource);
        if ($pubKey === false) {
            throw new KeyFormatException('从证书提取公钥失败: ' . openssl_error_string());
        }

        $keyData = openssl_pkey_get_details($pubKey);
        if ($keyData === false) {
            throw new KeyFormatException('获取公钥详情失败: ' . openssl_error_string());
        }

        return $keyData['key'];
    }

    /**
     * 获取证书的指纹
     *
     * @param string $certPem 证书PEM
     * @param string $algorithm 哈希算法 (sha1, sha256等)
     * @return string 指纹
     * @throws KeyFormatException 如果计算失败
     */
    public function getFingerprint(string $certPem, string $algorithm = 'sha256'): string
    {
        if (!$this->pemDerFormat->isValidPem($certPem)) {
            throw new KeyFormatException('无效的证书PEM格式');
        }

        // 验证算法
        $validAlgorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
        if (!in_array($algorithm, $validAlgorithms)) {
            throw new KeyFormatException('不支持的哈希算法: ' . $algorithm);
        }

        // 提取DER格式
        $derData = $this->pemDerFormat->pemToDer($certPem);
        
        // 计算指纹
        $fingerprint = hash($algorithm, $derData);
        if ($fingerprint === false) {
            throw new KeyFormatException('计算指纹失败');
        }

        // 格式化为冒号分隔的形式
        $formattedFingerprint = '';
        $length = strlen($fingerprint);
        for ($i = 0; $i < $length; $i += 2) {
            $formattedFingerprint .= substr($fingerprint, $i, 2) . ':';
        }

        return rtrim($formattedFingerprint, ':');
    }
} 