using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Qimmah.Security
{
    public static class Cryptography
    {
        static Cryptography()
        {
            _keyCache = new();
        }

        // Initialization vector - you can change this to your own random values
        private static readonly string _vector = "@1D2c3R4y5F6g7H8";

        // Hash algorithm name
        private static readonly string _hash = "SHA1";

        // Key size in bits
        private static readonly int _keySize = 256;

        // Number of iterations
        private static readonly int _iterations = 100000;

        // Cache for derived keys
        private static readonly ConcurrentDictionary<string, CachedKeyInfo> _keyCache = new();

        private class CachedKeyInfo
        {
            public byte[] Key { get; set; }
            public byte[] HmacKey { get; set; }
            public DateTime Created { get; set; }
        }

        // Key expiration time (e.g., 1 hour)
        private static readonly TimeSpan _keyCacheExpiration = TimeSpan.FromHours(1);

        // Maximum cache size
        private static readonly int _maxCacheSize = 5000;

        private static (byte[] Key, byte[] HmacKey) GetOrDeriveKeys(string password, byte[] salt)
        {
            var cacheKey = GenerateCacheKey(password, salt);

            // Clean expired keys
            if (_keyCache.Count > _maxCacheSize)
            {
                var expiredKeys = _keyCache
                    .Where(kvp => DateTime.UtcNow - kvp.Value.Created > _keyCacheExpiration)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in expiredKeys)
                {
                    _keyCache.TryRemove(key, out _);
                }
            }

            var cachedInfo = _keyCache.GetOrAdd(
                cacheKey,
                _ =>
                {
                    using var deriveBytes = new Rfc2898DeriveBytes(password, salt, _iterations, HashAlgorithmName.SHA256);
                    return new CachedKeyInfo
                    {
                        Key = deriveBytes.GetBytes(32),
                        HmacKey = deriveBytes.GetBytes(32),
                        Created = DateTime.UtcNow
                    };
                });

            return (cachedInfo.Key, cachedInfo.HmacKey);
        }

        private static string GenerateCacheKey(string password, byte[] salt)
        {
            using var hasher = SHA256.Create();
            var combined = Encoding.UTF8.GetBytes(password).Concat(salt).ToArray();
            var hash = hasher.ComputeHash(combined);
            return Convert.ToBase64String(hash);
        }

        public static string Encrypt<T>(T cipher, string plaintext, string password, TimeSpan ttl) where T : SymmetricAlgorithm
        { 
            // Generate unique salt and IV for each encryption
            byte[] salt = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            byte[] iv = new byte[cipher.BlockSize / 8];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }


            long expiryTicks = DateTime.UtcNow.Add(ttl).Ticks;
            byte[] expiryBytes = BitConverter.GetBytes(expiryTicks);

            // Get or derive keys using cache
            var (key, hmacKey) = GetOrDeriveKeys(password, salt);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext;

            // Perform encryption
            cipher.Mode = CipherMode.CBC;
            cipher.Padding = PaddingMode.PKCS7;

            using (ICryptoTransform encryptor = cipher.CreateEncryptor(key, iv))
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    csEncrypt.FlushFinalBlock();
                }

                ciphertext = msEncrypt.ToArray();
            }

            // Calculate HMAC
            using (var hmac = new HMACSHA256(hmacKey))
            {
                byte[] computedHmac = hmac.ComputeHash(
                    CombineArrays(salt, iv, BitConverter.GetBytes(ciphertext.Length), ciphertext)
                );

                // Combine all components
                var combined = new byte[
                    1 +                 // version
                    8 +                 // expiry
                    salt.Length +
                    iv.Length +
                    computedHmac.Length +
                    ciphertext.Length
                ];

                combined[0] = 1;

                int offset = 1;

                // expiry
                Buffer.BlockCopy(expiryBytes, 0, combined, offset, 8);
                offset += 8;

                // salt
                Buffer.BlockCopy(salt, 0, combined, offset, salt.Length);
                offset += salt.Length;

                // iv
                Buffer.BlockCopy(iv, 0, combined, offset, iv.Length);
                offset += iv.Length;

                // hmac
                Buffer.BlockCopy(computedHmac, 0, combined, offset, computedHmac.Length);
                offset += computedHmac.Length;

                // ciphertext
                Buffer.BlockCopy(ciphertext, 0, combined, offset, ciphertext.Length);

                return Convert.ToBase64String(combined);
            }
        }

        private static byte[] CombineArrays(params byte[][] arrays)
        {
            var combined = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, combined, offset, array.Length);
                offset += array.Length;
            }
            return combined;
        }



        public static string Decrypt<T>(T cipher, string ciphertext, string password)
            where T : SymmetricAlgorithm
        {
            try
            {
                byte[] combined = Convert.FromBase64String(ciphertext);

                if (combined.Length < 1 + 32 + cipher.BlockSize / 8 + 32)
                    throw new CryptographicException("Invalid ciphertext format");

                byte version = combined[0];
                if (version != 1)
                    throw new CryptographicException($"Unsupported version: {version}");

                // Extract components
                int offset = 1;

                // expiry
                byte[] expiryBytes = new byte[8];
                Buffer.BlockCopy(combined, offset, expiryBytes, 0, 8);
                offset += 8;

                long expiryTicks = BitConverter.ToInt64(expiryBytes, 0);
                DateTime expiry = new DateTime(expiryTicks, DateTimeKind.Utc);

                if (DateTime.UtcNow > expiry)
                    throw new CryptographicException("Encrypted value has expired"); 
                
                byte[] salt = new byte[32];
                Buffer.BlockCopy(combined, offset, salt, 0, salt.Length);
                offset += salt.Length;

                byte[] iv = new byte[cipher.BlockSize / 8];
                Buffer.BlockCopy(combined, offset, iv, 0, iv.Length);
                offset += iv.Length;

                byte[] storedHmac = new byte[32];
                Buffer.BlockCopy(combined, offset, storedHmac, 0, storedHmac.Length);
                offset += storedHmac.Length;

                byte[] ciphertextBytes = new byte[combined.Length - offset];
                Buffer.BlockCopy(combined, offset, ciphertextBytes, 0, ciphertextBytes.Length);

                // Get or derive keys using cache
                var (key, hmacKey) = GetOrDeriveKeys(password, salt);

                // Verify HMAC first
                using (var hmac = new HMACSHA256(hmacKey))
                {
                    byte[] computedHmac = hmac.ComputeHash(
                        CombineArrays(salt, iv, BitConverter.GetBytes(ciphertextBytes.Length), ciphertextBytes)
                    );

                    if (!computedHmac.SequenceEqual(storedHmac))
                        throw new CryptographicException("Message authentication failed");
                }

                // Proceed with decryption
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = cipher.CreateDecryptor(key, iv))
                using (MemoryStream msDecrypt = new MemoryStream(ciphertextBytes))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
            catch (Exception ex) when (ex is not CryptographicException)
            {
                throw new CryptographicException("Decryption failed");
            }
        }

        public static byte[] GenerateHmacKey(string password, string shaKey)
        {
            try
            {
                byte[] keyBytes = SHA256HMAC(Encoding.UTF8.GetBytes(password),
                                              Encoding.UTF8.GetBytes(shaKey));
                return keyBytes;
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }

        public static byte[] SHA256HMAC(byte[] data, byte[] key)
        {
            using (var hmacsha256 = new HMACSHA256(key))
            {
                byte[] hash = hmacsha256.ComputeHash(data);
                return hash;
            }
        }

    }
}
