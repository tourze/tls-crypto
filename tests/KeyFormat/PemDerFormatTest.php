<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\KeyFormat;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\CryptoFactory;
use Tourze\TLSCrypto\Exception\KeyFormatException;
use Tourze\TLSCrypto\KeyFormat\PemDerFormat;

/**
 * PEM/DER格式处理测试
 */
class PemDerFormatTest extends TestCase
{
    private PemDerFormat $pemDerFormat;

    protected function setUp(): void
    {
        $this->pemDerFormat = new PemDerFormat();
    }

    /**
     * 测试通过工厂创建PemDerFormat
     */
    public function testCreateViaFactory(): void
    {
        $pemDerFormat = CryptoFactory::createKeyFormat('basic');
        $this->assertInstanceOf(PemDerFormat::class, $pemDerFormat);
    }

    /**
     * 测试PEM格式有效性验证
     */
    public function testIsValidPem(): void
    {
        // 有效的PEM数据
        $validPem = "-----BEGIN CERTIFICATE-----\n"
            . "MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\n"
            . "A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\n"
            . "MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\n"
            . "YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\n"
            . "ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\n"
            . "CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\n"
            . "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD\n"
            . "+6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9\n"
            . "MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1\n"
            . "C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ\n"
            . "kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf\n"
            . "jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr\n"
            . "evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=\n"
            . "-----END CERTIFICATE-----";

        $this->assertTrue($this->pemDerFormat->isValidPem($validPem));

        // 无效的PEM数据 - 头尾不匹配
        $invalidPem1 = "-----BEGIN CERTIFICATE-----\n"
            . "MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\n"
            . "-----END PRIVATE KEY-----";
        $this->assertFalse($this->pemDerFormat->isValidPem($invalidPem1));

        // 无效的PEM数据 - 不是PEM格式
        $invalidPem2 = "This is not a PEM formatted data";
        $this->assertFalse($this->pemDerFormat->isValidPem($invalidPem2));

        // 无效的PEM数据 - Base64部分无效
        $invalidPem3 = "-----BEGIN CERTIFICATE-----\n"
            . "Invalid Base64 Data!!!\n"
            . "-----END CERTIFICATE-----";
        $this->assertFalse($this->pemDerFormat->isValidPem($invalidPem3));
    }

    /**
     * 测试PEM转DER
     */
    public function testPemToDer(): void
    {
        $validPem = "-----BEGIN CERTIFICATE-----\n"
            . "MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\n"
            . "A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\n"
            . "MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\n"
            . "YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\n"
            . "ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\n"
            . "CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\n"
            . "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD\n"
            . "+6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9\n"
            . "MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1\n"
            . "C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ\n"
            . "kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf\n"
            . "jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr\n"
            . "evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=\n"
            . "-----END CERTIFICATE-----";

        $der = $this->pemDerFormat->pemToDer($validPem);

        // 验证转换后的DER数据是二进制数据
        $this->assertTrue($this->pemDerFormat->isValidDer($der));

        // 测试无效PEM数据抛出异常
        $this->expectException(KeyFormatException::class);
        $this->pemDerFormat->pemToDer("Invalid PEM data");
    }

    /**
     * 测试DER转PEM
     */
    public function testDerToPem(): void
    {
        $validPem = "-----BEGIN CERTIFICATE-----\n"
            . "MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\n"
            . "A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\n"
            . "MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\n"
            . "YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\n"
            . "ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\n"
            . "CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\n"
            . "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD\n"
            . "+6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9\n"
            . "MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1\n"
            . "C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ\n"
            . "kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf\n"
            . "jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr\n"
            . "evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=\n"
            . "-----END CERTIFICATE-----";

        // PEM -> DER -> PEM 往返转换测试
        $der = $this->pemDerFormat->pemToDer($validPem);
        $pemAgain = $this->pemDerFormat->derToPem($der, 'CERTIFICATE');

        // 验证往返转换前后PEM有效性
        $this->assertTrue($this->pemDerFormat->isValidPem($pemAgain));

        // 移除换行和空格后比较内容
        $normalizedOriginal = preg_replace('/\s+/', '', $validPem);
        $normalizedConverted = preg_replace('/\s+/', '', $pemAgain);
        $this->assertEquals($normalizedOriginal, $normalizedConverted);

        // 测试无效DER数据抛出异常
        $this->expectException(KeyFormatException::class);
        $this->pemDerFormat->derToPem('Invalid DER data', 'CERTIFICATE');
    }

    /**
     * 测试从PEM提取数据
     */
    public function testExtractFromPem(): void
    {
        $validPem = "-----BEGIN CERTIFICATE-----\n"
            . "MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\n"
            . "A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\n"
            . "MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\n"
            . "YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\n"
            . "ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\n"
            . "CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\n"
            . "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD\n"
            . "+6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9\n"
            . "MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1\n"
            . "C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ\n"
            . "kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf\n"
            . "jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr\n"
            . "evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=\n"
            . "-----END CERTIFICATE-----";

        $extracted = $this->pemDerFormat->extractFromPem($validPem);

        $this->assertIsArray($extracted);
        $this->assertArrayHasKey('type', $extracted);
        $this->assertArrayHasKey('data', $extracted);
        $this->assertEquals('CERTIFICATE', $extracted['type']);
        $this->assertIsString($extracted['data']);

        // 测试无效PEM数据抛出异常
        $this->expectException(KeyFormatException::class);
        $this->pemDerFormat->extractFromPem("Invalid PEM data");
    }
} 