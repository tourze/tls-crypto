<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto;

use Tourze\TLSCrypto\AsymmetricCipher\DSA;
use Tourze\TLSCrypto\AsymmetricCipher\ECDSA;
use Tourze\TLSCrypto\AsymmetricCipher\Ed25519;
use Tourze\TLSCrypto\AsymmetricCipher\Ed448;
use Tourze\TLSCrypto\AsymmetricCipher\RSA;
use Tourze\TLSCrypto\Cipher\AesCbc;
use Tourze\TLSCrypto\Cipher\AesCtr;
use Tourze\TLSCrypto\Cipher\AesGcm;
use Tourze\TLSCrypto\Cipher\ChaCha20Poly1305;
use Tourze\TLSCrypto\Contract\AsymmetricCipherInterface;
use Tourze\TLSCrypto\Contract\CipherInterface;
use Tourze\TLSCrypto\Contract\CurveInterface;
use Tourze\TLSCrypto\Contract\HashInterface;
use Tourze\TLSCrypto\Contract\KdfInterface;
use Tourze\TLSCrypto\Contract\KeyExchangeInterface;
use Tourze\TLSCrypto\Contract\MacInterface;
use Tourze\TLSCrypto\Contract\RandomInterface;
use Tourze\TLSCrypto\Exception\CryptoException;
use Tourze\TLSCrypto\Hash\SHA256;
use Tourze\TLSCrypto\Hash\SHA384;
use Tourze\TLSCrypto\Hash\SHA512;
use Tourze\TLSCrypto\Kdf\HKDF;
use Tourze\TLSCrypto\KeyExchange\ECDHE;
use Tourze\TLSCrypto\KeyExchange\X25519;
use Tourze\TLSCrypto\KeyExchange\X448;
use Tourze\TLSCrypto\Mac\HMAC;
use Tourze\TLSCrypto\Random\CryptoRandom;

/**
 * 加密组件工厂类
 */
class CryptoFactory
{
    /**
     * 创建随机数生成器
     *
     * @return RandomInterface
     */
    public static function createRandom(): RandomInterface
    {
        return new CryptoRandom();
    }

    /**
     * 创建哈希函数
     *
     * @param string $algorithm 哈希算法名称
     * @return HashInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createHash(string $algorithm): HashInterface
    {
        return match ($algorithm) {
            'sha256' => new SHA256(),
            'sha384' => new SHA384(),
            'sha512' => new SHA512(),
            default => throw new CryptoException('不支持的哈希算法: ' . $algorithm),
        };
    }

    /**
     * 创建消息认证码
     *
     * @param string $algorithm MAC算法名称
     * @param array $options 选项
     * @return MacInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createMac(string $algorithm, array $options = []): MacInterface
    {
        if (str_starts_with($algorithm, 'hmac-')) {
            $hashAlgorithm = substr($algorithm, 5);
            $hash = self::createHash($hashAlgorithm);
            return new HMAC($hash);
        }

        throw new CryptoException('不支持的MAC算法: ' . $algorithm);
    }

    /**
     * 创建对称加密算法
     *
     * @param string $algorithm 加密算法名称
     * @param array $options 选项
     * @return CipherInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createCipher(string $algorithm, array $options = []): CipherInterface
    {
        if (preg_match('/^aes-(\d+)-gcm$/', $algorithm, $matches)) {
            $keySize = (int) $matches[1];
            return new AesGcm($keySize);
        }

        if (preg_match('/^aes-(\d+)-cbc$/', $algorithm, $matches)) {
            $keySize = (int) $matches[1];
            return new AesCbc($keySize);
        }

        if (preg_match('/^aes-(\d+)-ctr$/', $algorithm, $matches)) {
            $keySize = (int) $matches[1];
            return new AesCtr($keySize);
        }

        if ($algorithm === 'chacha20-poly1305') {
            return new ChaCha20Poly1305();
        }

        throw new CryptoException('不支持的加密算法: ' . $algorithm);
    }

    /**
     * 创建密钥导出函数
     *
     * @param string $algorithm KDF算法名称
     * @param array $options 选项
     * @return KdfInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createKdf(string $algorithm, array $options = []): KdfInterface
    {
        if (str_starts_with($algorithm, 'hkdf-')) {
            $hashAlgorithm = substr($algorithm, 5);
            $hash = self::createHash($hashAlgorithm);
            return new HKDF($hash);
        }

        throw new CryptoException('不支持的KDF算法: ' . $algorithm);
    }

    /**
     * 创建非对称加密算法
     *
     * @param string $algorithm 算法名称
     * @param array $options 选项
     * @return AsymmetricCipherInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createAsymmetricCipher(string $algorithm, array $options = []): AsymmetricCipherInterface
    {
        return match ($algorithm) {
            'rsa' => new RSA(),
            'ed25519' => new Ed25519(),
            'ed448' => new Ed448(),
            'ecdsa' => new ECDSA(),
            'dsa' => new DSA(),
            default => throw new CryptoException('不支持的非对称加密算法: ' . $algorithm),
        };
    }

    /**
     * 创建密钥交换算法
     *
     * @param string $algorithm 算法名称
     * @param array $options 选项
     * @return KeyExchangeInterface
     * @throws CryptoException 如果算法不支持
     */
    public static function createKeyExchange(string $algorithm, array $options = []): KeyExchangeInterface
    {
        return match ($algorithm) {
            'x25519' => new X25519(),
            'x448' => new X448(),
            'ecdhe' => new ECDHE(),
            default => throw new CryptoException('不支持的密钥交换算法: ' . $algorithm),
        };
    }

    /**
     * 创建椭圆曲线
     *
     * @param string $curveName 曲线名称
     * @return CurveInterface
     * @throws CryptoException 如果曲线不支持
     */
    public static function createCurve(string $curveName): CurveInterface
    {
        return match ($curveName) {
            'nistp256', 'p-256' => new Curve\NISTP256(),
            'nistp384', 'p-384' => new Curve\NISTP384(),
            'nistp521', 'p-521' => new Curve\NISTP521(),
            'curve25519' => new Curve\Curve25519(),
            'curve448' => new Curve\Curve448(),
            default => throw new CryptoException('不支持的椭圆曲线: ' . $curveName),
        };
    }
}
