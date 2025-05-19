<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Hash;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\HashException;
use Tourze\TLSCrypto\Hash\MD5;

class MD5Test extends TestCase
{
    public function testGetName(): void
    {
        $hash = new MD5();
        $this->assertEquals('md5', $hash->getName());
    }

    public function testGetOutputLength(): void
    {
        $hash = new MD5();
        $this->assertEquals(16, $hash->getOutputLength());
    }

    public function testGetBlockSize(): void
    {
        $hash = new MD5();
        $this->assertEquals(64, $hash->getBlockSize());
    }

    public function testHashWithKnownValues(): void
    {
        $hash = new MD5();
        // Test vector for MD5("")
        $this->assertEquals(hex2bin('d41d8cd98f00b204e9800998ecf8427e'), $hash->hash(''));
        // Test vector for MD5("abc")
        $this->assertEquals(hex2bin('900150983cd24fb0d6963f7d28e17f72'), $hash->hash('abc'));
        // Test vector for MD5("The quick brown fox jumps over the lazy dog")
        $this->assertEquals(hex2bin('9e107d9d372bb6826bd81d3542a419d6'), $hash->hash('The quick brown fox jumps over the lazy dog'));
    }

    public function testStreamingHash(): void
    {
        $hash = new MD5();
        $context = $hash->createContext();
        $hash->updateContext($context, 'The quick ');
        $hash->updateContext($context, 'brown fox jumps ');
        $hash->updateContext($context, 'over the lazy dog');
        $finalHash = $hash->finalizeContext($context);
        $this->assertEquals(hex2bin('9e107d9d372bb6826bd81d3542a419d6'), $finalHash);
    }

    public function testCreateContextFailureSimulation(): void
    {
        // Similar to SHA1Test, assume hash_init('md5') works.
        try {
            $hash = new MD5();
            $context = $hash->createContext();
            $this->assertIsObject($context); // PHP 8 hash contexts are objects
        } catch (HashException $e) {
            $this->fail('MD5 createContext threw an exception unexpectedly: ' . $e->getMessage());
        }
    }
}
