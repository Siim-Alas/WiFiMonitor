using System.IO;
using System.Security.Cryptography;

namespace WiFiMonitorClassLibrary
{
    public static class CryptographyWrapper
    {
        /// <summary>
        /// Decrypts a Stream with the AES algorithm.
        /// </summary>
        /// <param name="streamToDecrypt">The stream to decrypt.</param>
        /// <param name="key">The key used in encrypting the stream.</param>
        /// <param name="initializationVector">The initialization vectors used in decrypting the stream.</param>
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
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

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
        /// Pseudo-random function to produce n bits.
        /// </summary>
        /// <param name="n">The amount of bits to produce, assumed to be a multiple of 8.</param>
        /// <param name="secretKey">K, the secret key used in producing the bits.</param>
        /// <param name="specificText">A, the application specific text used in producing the bits.</param>
        /// <param name="specificData">B, the application specific data used in producing the bits.</param>
        /// <returns>The pseudo-random bits, stored in a byte array.</returns>
        public static byte[] PRFn(
            int n, 
            byte[] secretKey, 
            byte[] specificText, 
            byte[] specificData)
        {
            byte[] resultBytes = new byte[(n / 8) + ((n / 8) % 20)];
            byte[] argumentBytes = new byte[specificText.Length + 1 + specificData.Length + 1];
            byte[] hashResult = new byte[20];

            specificText.CopyTo(argumentBytes, 0);
            specificData.CopyTo(argumentBytes, specificText.Length + 1);

            using HMACSHA1 sha1 = new HMACSHA1(secretKey);
            for (byte i = 0; i * 20 < resultBytes.Length; i++)
            {
                argumentBytes[^1] = i;
                hashResult = sha1.ComputeHash(argumentBytes);
                hashResult.CopyTo(resultBytes, i * 20);
            }

            return resultBytes[0..((n / 8) - 1)];
        }
    }
}
