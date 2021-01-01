using System;
using System.Security.Cryptography;
using System.Reflection;

namespace WiFiMonitorClassLibrary.Cryptography
{
    /// <summary>
    /// An abstraction of various cryptographic operations from the System.Security.Cryptohraphy 
    /// namespace.
    /// </summary>
    public static class CryptographyWrapper
    {
        /// <summary>
        /// The numbers of bits (translated into bytes) supported by the pseudo-random function.
        /// </summary>
        public enum PRFBitValues
        {
            bit128 = 128 / 8,
            bit256 = 256 / 8,
            bit384 = 384 / 8,
            bit512 = 512 / 8,
        }
        /// <summary>
        /// Encrypts or decrypts a byte array with the AES Counter (CTR) mode.
        /// Note that for this algorithm, encryption and decryption are identical. Decryption
        /// consists of encrypting the encrypted byte array again with the same initial counter
        /// and key used during encryption.
        /// </summary>
        /// <param name="bytesToEncrypt">The byte array to be encrypted.</param>
        /// <param name="initialCounter">
        /// The first block used during encryption, which has to be equal in length to the block
        /// size used during encryption (128 bits or 16 bytes for CCMP).
        /// </param>
        /// <param name="key">The key used during encryption.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] AESCounterModeEncryptBytes(
            byte[] bytesToEncrypt,
            byte[] initialCounter,
            byte[] key)
        {
            // Inspired by https://gist.github.com/hanswolff/8809275
            if (bytesToEncrypt == null)
            {
                throw new ArgumentNullException(
                    "The bytes to encrypt were null", nameof(bytesToEncrypt));
            }
            if (key == null)
            {
                throw new ArgumentNullException("The key provided was null", nameof(key));
            }
            const int blockSizeInBytes = 128 / 8;
            if (initialCounter.Length != blockSizeInBytes)
            {
                throw new ArgumentException(
                    "The initialCounter provided isn't 128 bits or 16 bytes long.", 
                    nameof(initialCounter));
            }

            byte[] counterBlock = new byte[128 / 8];
            byte[] encryptedBytes = new byte[bytesToEncrypt.Length];
            byte[] encryptedCounterBlock = new byte[blockSizeInBytes];

            initialCounter.CopyTo(counterBlock, 0);

            using Aes aesAlg = new AesManaged()
            {
                // AesManaged defaults to 128-bit block size
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            // Integer division rounds towards zero, so this will omit any partial block at the end
            for (int i = 0; i < bytesToEncrypt.Length / blockSizeInBytes; i++)
            {
                // Encrypt the counter block in ECB mode
                using ICryptoTransform transform = aesAlg.CreateEncryptor(key, counterBlock);
                transform.TransformBlock(counterBlock, 0, blockSizeInBytes, encryptedCounterBlock, 0);

                // XOR the encrypted counter block with the respective bytes to encrypt
                int j;
                for (j = 0; j < blockSizeInBytes; j++)
                {
                    encryptedBytes[(i * blockSizeInBytes) + j] = 
                        (byte)(encryptedCounterBlock[j] ^ 
                            bytesToEncrypt[(i * blockSizeInBytes) + j]);
                }
                // j is now set to blockSizeInBytes.

                // Starting from the last byte in counterBlock, increment the counter by one. 
                // If the byte overflows, go to the next byte (coming from the end).
                while(++counterBlock[--j] == 0) { }
            }

            // In case there is any partial block left at the end, encrypt that as well
            int lastBlockLengthInBytes = bytesToEncrypt.Length % blockSizeInBytes;
            if (lastBlockLengthInBytes > 0)
            {
                using ICryptoTransform transform = aesAlg.CreateEncryptor(key, counterBlock);
                transform.TransformBlock(
                    counterBlock, 0, blockSizeInBytes, encryptedCounterBlock, 0);

                for (int j = 0; j < lastBlockLengthInBytes; j++)
                {
                    encryptedBytes[(bytesToEncrypt.Length - lastBlockLengthInBytes) + j] =
                        (byte)(encryptedCounterBlock[j] ^ 
                            bytesToEncrypt[(bytesToEncrypt.Length - lastBlockLengthInBytes) + j]);
                }
            }

            return encryptedBytes;
        }
        /// <summary>
        /// Password-Based Key Derivation Function 2, used among others by WPA2 to derive the PSK
        /// from the Access point password. This implementation uses HMAC-SHA1 as the Pseudo-Random 
        /// Function (PRF).
        /// </summary>
        /// <param name="password">
        /// The password used to derive the key. In the case of WPA2, this is the password of the
        /// Access Point (AP) to which the Station (STA) is connecting.
        /// </param>
        /// <param name="salt">
        /// The "cryptographic salt" used to derive the key, the bssid in the case of WPA2.
        /// </param>
        /// <param name="numberOfIterations">
        /// The number of iterations performed by the function, 4096 in the case of WPA2.
        /// </param>
        /// <param name="keyLengthInBytes">
        /// The length of the derived key in bytes, 32 (representing 256 bits) in the case of WPA2.
        /// </param>
        /// <returns>The derived key.</returns>
        public static byte[] PBKDF2(
            byte[] password, 
            byte[] salt, 
            int numberOfIterations, 
            int keyLengthInBytes)
        {
            if (salt.Length >= 8)
            {
                // Salt lengths of less than 8 throw ArgumentException
                using Rfc2898DeriveBytes encryptor = 
                    new Rfc2898DeriveBytes(password, salt, numberOfIterations);
                return encryptor.GetBytes(keyLengthInBytes);
            }
            else 
            {
                // The Rfc2898DeriveBytes class: https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.Algorithms/src/System/Security/Cryptography/Rfc2898DeriveBytes.cs
                // This is a hack and may thus be broken with subsequent versions

                // Pass a dummy byte array of length 8 to not get ArgumentException
                using Rfc2898DeriveBytes encryptor = 
                    new Rfc2898DeriveBytes(password, new byte[8], numberOfIterations);

                // Use System.Reflection to set the private field "_salt" on the encryptor
                FieldInfo saltFieldInfo = typeof(Rfc2898DeriveBytes).GetField(
                    "_salt", BindingFlags.NonPublic | BindingFlags.Instance);
                saltFieldInfo.SetValue(encryptor, salt);

                // Now that the encryptor has the proper salt, get the bytes as usual
                return encryptor.GetBytes(keyLengthInBytes);
            }
        }
        /// <summary>
        /// Pseudo-Random Function to produce n bits.
        /// </summary>
        /// <param name="n">The amount of bits to produce.</param>
        /// <param name="secretKey">K, the secret key used in producing the bits.</param>
        /// <param name="specificText">
        /// A, the application specific text used in producing the bits.
        /// </param>
        /// <param name="specificData">
        /// B, the application specific data used in producing the bits.
        /// </param>
        /// <returns>The pseudo-random bits, stored in a byte array of length n / 8.</returns>
        public static byte[] PRFn(
            PRFBitValues n, 
            byte[] secretKey, 
            byte[] specificText, 
            byte[] specificData)
        {
            // n will never be a multiple of 20 bytes
            byte[] resultBytes = new byte[20 * (((int)n / 20) + 1)];
            byte[] argumentBytes = new byte[specificText.Length + 1 + specificData.Length + 1];
            byte[] hashResult;

            specificText.CopyTo(argumentBytes, 0);
            specificData.CopyTo(argumentBytes, specificText.Length + 1);

            using HMACSHA1 sha1 = new HMACSHA1(secretKey);
            for (byte i = 0; i * 20 < resultBytes.Length; i++)
            {
                argumentBytes[^1] = i;
                hashResult = sha1.ComputeHash(argumentBytes);
                hashResult.CopyTo(resultBytes, i * 20);
            }

            return resultBytes[0..(int)n];
        }
    }
}
