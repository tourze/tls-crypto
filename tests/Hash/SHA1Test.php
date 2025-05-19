<?php

declare(strict_types=1);

namespace Tourze\TLSCrypto\Tests\Hash;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCrypto\Exception\HashException;
use Tourze\TLSCrypto\Hash\SHA1;

class SHA1Test extends TestCase
{
    public function testGetName(): void
    {
        $hash = new SHA1();
        $this->assertEquals('sha1', $hash->getName());
    }

    public function testGetOutputLength(): void
    {
        $hash = new SHA1();
        $this->assertEquals(20, $hash->getOutputLength());
    }

    public function testGetBlockSize(): void
    {
        $hash = new SHA1();
        $this->assertEquals(64, $hash->getBlockSize());
    }

    public function testHashWithKnownValues(): void
    {
        $hash = new SHA1();
        // Test vector for SHA-1("")
        $this->assertEquals(hex2bin('da39a3ee5e6b4b0d3255bfef95601890afd80709'), $hash->hash(''));
        // Test vector for SHA-1("abc")
        $this->assertEquals(hex2bin('a9993e364706816aba3e25717850c26c9cd0d89d'), $hash->hash('abc'));
        // Test vector for SHA-1("The quick brown fox jumps over the lazy dog")
        $this->assertEquals(hex2bin('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'), $hash->hash('The quick brown fox jumps over the lazy dog'));
    }

    public function testStreamingHash(): void
    {
        $hash = new SHA1();
        $context = $hash->createContext();
        $hash->updateContext($context, 'The quick ');
        $hash->updateContext($context, 'brown fox jumps ');
        $hash->updateContext($context, 'over the lazy dog');
        $finalHash = $hash->finalizeContext($context);
        $this->assertEquals(hex2bin('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'), $finalHash);
    }

    public function testCreateContextFailureSimulation(): void
    {
        // Hard to simulate hash_init failure without changing global state or specific PHP builds.
        // We assume hash_init('sha1') generally works.
        // If it were to fail, the constructor should throw HashException.
        // For now, we ensure it doesn't throw under normal conditions.
        try {
            $hash = new SHA1();
            $context = $hash->createContext();
            $this->assertIsObject($context); // PHP 8 hash contexts are objects
        } catch (HashException $e) {
            $this->fail('SHA1 createContext threw an exception unexpectedly: ' . $e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }
}
