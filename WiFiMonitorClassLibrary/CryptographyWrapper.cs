using System;
using System.IO;
using System.Security.Cryptography;

namespace WiFiMonitorClassLibrary
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
        /// Decrypts a Stream with the AES algorithm.
        /// </summary>
        /// <param name="streamToDecrypt">The stream to decrypt.</param>
        /// <param name="key">The key used in encrypting the stream.</param>
        /// <param name="initializationVector">
        /// The initialization vectors used in decrypting the stream.
        /// </param>
        /// <param name="cipherMode">The cipher mode used in decrypting the stream.</param>
        /// <returns>The decrypted stream.</returns>
        public static CryptoStream AESDecryptStream(
            Stream streamToDecrypt, 
            byte[] key, 
            byte[] initializationVector, 
            CipherMode cipherMode = CipherMode.CBC)
        {
            using Aes aesAlg = new AesManaged() 
            {
                // AesManaged limits block sizes to 128 bits
                IV = initializationVector,
                Key = key,
                // KeySize = key.Length * 8,
                Mode = cipherMode
            };
            using ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using CryptoStream decryptedCryptoStream = new CryptoStream(
                streamToDecrypt, decryptor, CryptoStreamMode.Read);
            
            return decryptedCryptoStream;
        }
        /// <summary>
        /// Decrypts a byte array with the AES CCM algorithm.
        /// </summary>
        /// <param name="bytesToDecrypt">The byte array to decrypt.</param>
        /// <param name="key">The key used in encrypting the byte array.</param>
        /// <param name="nonce">The "number used only once" used in encrypting the byte array.</param>
        /// <param name="tag">The authentication tag produced during encryption.</param>
        /// <returns>The decrypted byte array.</returns>
        public static byte[] AESCCMDecryptBytes(
            byte[] bytesToDecrypt,
            byte[] key,
            byte[] nonce,
            byte[] tag)
        {
            byte[] decryptedBytes = new byte[bytesToDecrypt.Length];
            using AesCcm aesCcm = new AesCcm(key);
            aesCcm.Decrypt(nonce, bytesToDecrypt, tag, decryptedBytes);
            return decryptedBytes;
        }
        /// <summary>
        /// Decrypts a byte array with the AES Counter decryption algorithm.
        /// </summary>
        /// <param name="bytesToDecrypt">
        /// The byte array to be decrypted, assumed to have a length divisible by the block size 
        /// used during encryption (128 bits or 16 bytes for CCMP).
        /// </param>
        /// <param name="key">The key used during encryption.</param>
        /// <param name="counterBlock">
        /// The first block used during encryption, assumed to be equal in length to the block
        /// size used during encryption (128 bits or 16 bytes for CCMP). It will get mutated
        /// during encryption.
        /// </param>
        /// <returns>The decrypted byte array.</returns>
        public static byte[] AESCounterModeDecryptBytes(
            byte[] bytesToDecrypt,
            byte[] key,
            byte[] counterBlock)
        {
            // Inspired by https://gist.github.com/hanswolff/8809275
            using Aes aesAlg = new AesManaged()
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            int blockSizeInBytes = 128 / 8;
            byte[] encryptedCounterBlock = new byte[blockSizeInBytes];
            byte[] decryptedBytes = new byte[bytesToDecrypt.Length];

            for (int i = 0; i < bytesToDecrypt.Length / blockSizeInBytes; i++)
            {
                // Encrypt the counter block in ECB mode
                using ICryptoTransform transform = aesAlg.CreateEncryptor(key, counterBlock);
                transform.TransformBlock(counterBlock, 0, blockSizeInBytes, encryptedCounterBlock, 0);

                // XOR the encrypted counter block with the respective bytes to decrypt
                int j;
                for (j = 0; j < blockSizeInBytes; j++)
                {
                    decryptedBytes[(i * blockSizeInBytes) + j] = 
                        (byte)(encryptedCounterBlock[j] | bytesToDecrypt[j]);
                }
                // j is now set to blockSizeInBytes.

                // Starting from the last byte in counterBlock, increment by one. 
                // If the byte overflows, go to the next byte (coming from the end).
                while(++counterBlock[--j] == 0) { }
            }

            return decryptedBytes;
        }
        /// <summary>
        /// Pseudo-random function to produce n bits.
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
            byte[] resultBytes = new byte[(int)n + ((int)n % 20)];
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

            return resultBytes[0..((int)n - 1)];
        }
    }
}
