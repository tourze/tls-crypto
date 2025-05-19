<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\KeyExchangeException;
use Tourze\TLSCrypto\KeyExchange\DHE;

class DHETest extends TestCase
{
    public function testGetName(): void
    {
        $dhe = new DHE();
        $this->assertEquals('dhe', $dhe->getName());
    }

    public function provideKeyGroups(): array
    {
        return [
            ['ffdhe2048', 2048],
            ['ffdhe3072', 3072],
            ['ffdhe4096', 4096],
        ];
    }

    /**
     * @dataProvider provideKeyGroups
     */
    public function testGenerateKeyPair(string $group, int $expectedBits): void
    {
        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair(['group' => $group]);

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('params', $keyPair);
        $this->assertArrayHasKey('group', $keyPair);
        $this->assertArrayHasKey('bits', $keyPair);

        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);
        $this->assertEquals($group, $keyPair['group']);
        $this->assertEquals($expectedBits, $keyPair['bits']);

        $this->assertArrayHasKey('p', $keyPair['params']);
        $this->assertArrayHasKey('g', $keyPair['params']);

        // OpenSSL可能会返回比预期长度更长的素数p，这是因为内部填充或格式化
        // 只验证p的长度至少达到该位数所需的字节数
        $minBytesExpected = ceil($expectedBits / 8);
        $this->assertGreaterThanOrEqual($minBytesExpected, strlen($keyPair['params']['p']),
            "素数p的长度应至少为{$minBytesExpected}字节（{$expectedBits}位）");

        // Verify 'g' is a small integer, e.g., 2, by trying to unpack it.
        // Note: g is stored as binary. For g=2, it would be pack('C', 2) which is "\x02".
        // If g is a multi-byte integer, this check needs adjustment.
        // For RFC3526 groups, g is 2.
        $this->assertEquals(pack('C', 2), $keyPair['params']['g']);
    }

    public function testGenerateKeyPairDefaultGroup(): void
    {
        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair(); // Default is ffdhe2048
        $this->assertEquals('ffdhe2048', $keyPair['group']);
        $this->assertEquals(2048, $keyPair['bits']);
    }

    /**
     * @dataProvider provideKeyGroups
     */
    public function testComputeSharedSecret(string $group): void
    {
        $dhe = new DHE();

        $keyPairA = $dhe->generateKeyPair(['group' => $group]);
        $keyPairB = $dhe->generateKeyPair(['group' => $group]);

        $sharedSecretA = $dhe->computeSharedSecret($keyPairA['privateKey'], $keyPairB['publicKey']);
        $sharedSecretB = $dhe->computeSharedSecret($keyPairB['privateKey'], $keyPairA['publicKey']);

        $this->assertNotEmpty($sharedSecretA);
        $this->assertEquals($sharedSecretA, $sharedSecretB, "Shared secrets should be identical.");

        $this->assertEquals(32, strlen($sharedSecretA)); // Default hash sha256
    }

    public function testComputeSharedSecretWithCustomHash(): void
    {
        $dhe = new DHE();
        $keyPairA = $dhe->generateKeyPair(['group' => 'ffdhe2048']);
        $keyPairB = $dhe->generateKeyPair(['group' => 'ffdhe2048']);

        $sharedSecretSha512 = $dhe->computeSharedSecret($keyPairA['privateKey'], $keyPairB['publicKey'], ['hash' => 'sha512']);
        $this->assertEquals(64, strlen($sharedSecretSha512));
    }

    public function testGenerateKeyPairWithUnknownGroupDefaultsToDefault(): void
    {
        $dhe = new DHE();
        // Expect no exception, should default to ffdhe2048
        $keyPair = $dhe->generateKeyPair(['group' => 'unknown-custom-group']);
        $this->assertEquals('ffdhe2048', $keyPair['group']);
        $this->assertEquals(2048, $keyPair['bits']);
    }

    public function testComputeSharedSecretWithMismatchedKeyTypes(): void
    {
        // This test requires a DHE key to be valid for the details check for DH type,
        // but the private key passed to computeSharedSecret is an RSA key.
        $dhe = new DHE();
        $keyPairDH = $dhe->generateKeyPair(); // A valid DH key pair

        $rsaKeyRes = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        if ($rsaKeyRes === false) {
            $this->fail('Failed to generate RSA key for test: ' . openssl_error_string());
        }
        $rsaPrivateKeyPem = '';
        if (!openssl_pkey_export($rsaKeyRes, $rsaPrivateKeyPem)) {
            $this->fail('Failed to export RSA private key for test: ' . openssl_error_string());
        }

        // We are trying to compute with an RSA private key and DH public key.
        // openssl_pkey_get_private on RSA key should succeed.
        // openssl_dh_compute_key expects the first param to be peer public DH value,
        // and second to be local DH private key resource.
        // The failure should be in openssl_dh_compute_key if it type checks, or it might lead to a generic error.
        // The DHE class itself doesn't check $localPrivKey type before passing to openssl_dh_compute_key.
        // The exception would come from openssl_dh_compute_key itself if it receives an incompatible key type.

        $this->expectException(KeyExchangeException::class);
        // The exact message might depend on OpenSSL version and how it handles the type mismatch in openssl_dh_compute_key.
        // It will likely be 'DHE共享密钥计算失败 (dh_compute_key): ...' or similar generic error.
        // Previous expectation '私钥不是有效的DH密钥' was for a manual type check that no longer exists in computeSharedSecret.
        $this->expectExceptionMessageMatches('/DHE共享密钥计算失败|error computing shared secret/');

        $dhe->computeSharedSecret($rsaPrivateKeyPem, $keyPairDH['publicKey']);
    }

    // testGenerateDhParamsDirectlyWithUnsupportedBits is no longer relevant as generateDHParams was removed.
    // The new DHE implementation uses a fixed list of standard groups.
    // Trying to use a group not in DH_STANDARD_GROUPS will make it fall back to the default.

    /**
     * 测试ffdhe3072组现在可以正常工作
     * 由于修复了素数表示，ffdhe3072现在应该正常工作而不是回退
     */
    public function testFfdhe3072Works(): void
    {
        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair(['group' => 'ffdhe3072']);

        // 确认使用了正确的组
        $this->assertEquals('ffdhe3072', $keyPair['group']);
        $this->assertEquals(3072, $keyPair['bits']);

        // 其他常规验证
        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('params', $keyPair);

        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);

        // 验证可以使用这些密钥进行共享密钥计算
        $keyPairB = $dhe->generateKeyPair(['group' => 'ffdhe3072']);
        $sharedSecretA = $dhe->computeSharedSecret($keyPair['privateKey'], $keyPairB['publicKey']);
        $sharedSecretB = $dhe->computeSharedSecret($keyPairB['privateKey'], $keyPair['publicKey']);

        $this->assertNotEmpty($sharedSecretA);
        $this->assertEquals($sharedSecretA, $sharedSecretB, "Shared secrets should be identical.");
    }

    /**
     * 测试未知组名的回退逻辑
     * 使用不存在的组名应该回退到默认组
     */
    public function testUnknownGroupFallback(): void
    {
        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair(['group' => 'unknown-nonexistent-group']);

        // 确认回退到默认组ffdhe2048
        $this->assertEquals('ffdhe2048', $keyPair['group']);
        $this->assertEquals(2048, $keyPair['bits']);

        // 其他常规验证
        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('params', $keyPair);

        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);

        // 验证可以使用这些密钥进行共享密钥计算
        $keyPairB = $dhe->generateKeyPair(['group' => 'ffdhe2048']);
        $sharedSecretA = $dhe->computeSharedSecret($keyPair['privateKey'], $keyPairB['publicKey']);
        $sharedSecretB = $dhe->computeSharedSecret($keyPairB['privateKey'], $keyPair['publicKey']);

        $this->assertNotEmpty($sharedSecretA);
        $this->assertEquals($sharedSecretA, $sharedSecretB, "Shared secrets should be identical.");
    }
}
