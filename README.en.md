# TLS-Crypto

This package implements the cryptographic algorithms and functionalities required for the TLS protocol, including:

## Features

- Symmetric encryption algorithms: AES-GCM, AES-CBC, ChaCha20-Poly1305, 3DES, etc.
- Asymmetric encryption algorithms: RSA, ECDSA, EdDSA, DSA, etc.
- Key exchange algorithms: ECDHE, DHE, RSA, etc.
- Hash functions: SHA-256, SHA-384, SHA-512, MD5, etc.
- Message authentication codes: HMAC, AEAD, GMAC, etc.
- Random number generator: CSPRNG
- Key derivation functions: HKDF
- Curve implementations: P-256, P-384, X25519, X448, etc.

## Requirements

- PHP 8.1+
- ext-ctype
- psr/log

## Installation

```bash
composer require tourze/tls-crypto
```

## Basic Usage

### Random Number Generation

```php
use Tourze\TLSCrypto\CryptoFactory;

// Create a random number generator
$random = CryptoFactory::createRandom();

// Generate 16 bytes of random data
$randomBytes = $random->getRandomBytes(16);

// Generate a random integer between 1 and 100
$randomInt = $random->getRandomInt(1, 100);
```

### Hash Functions

```php
use Tourze\TLSCrypto\CryptoFactory;

// Create a SHA-256 hash function
$hash = CryptoFactory::createHash('sha256');

// Calculate hash value
$data = 'Hello, World!';
$hashValue = $hash->hash($data);

// Using incremental hashing
$context = $hash->createContext();
$hash->updateContext($context, 'Hello, ');
$hash->updateContext($context, 'World!');
$hashValue = $hash->finalizeContext($context);
```

### HMAC Message Authentication Code

```php
use Tourze\TLSCrypto\CryptoFactory;

// Create an HMAC based on SHA-256
$hmac = CryptoFactory::createMac('hmac-sha256');

// Calculate HMAC
$data = 'Message to authenticate';
$key = $random->getRandomBytes(32);
$mac = $hmac->compute($data, $key);

// Verify HMAC
$isValid = $hmac->verify($data, $mac, $key);
```

### AES-GCM Encryption

```php
use Tourze\TLSCrypto\CryptoFactory;

// Create AES-256-GCM encryption algorithm
$cipher = CryptoFactory::createCipher('aes-256-gcm');

// Generate random key and IV
$random = CryptoFactory::createRandom();
$key = $random->getRandomBytes($cipher->getKeyLength());
$iv = $random->getRandomBytes($cipher->getIVLength());

// Encrypt data
$plaintext = 'Secret message';
$aad = 'Additional authenticated data';
$tag = null;
$ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

// Decrypt data
$decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);
```

### HKDF Key Derivation

```php
use Tourze\TLSCrypto\CryptoFactory;

// Create HKDF based on SHA-256
$kdf = CryptoFactory::createKdf('hkdf-sha256');

// Derive key material
$secret = 'Master secret';
$salt = 'Salt value';
$info = 'Key expansion';
$length = 32; // Derive 32 bytes of key material
$derivedKey = $kdf->derive($secret, $salt, $info, $length);
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 