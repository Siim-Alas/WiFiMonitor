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
        /// Encrypts or decrypts a byte array with the AES Counter with Cbc-Mac (CCM) mode.
        /// Note that for this algorithm, encryption and decryption are identical. Decryption
        /// consists of encrypting the encrypted byte array again with the same nonce
        /// and key used during encryption.
        /// </summary>
        /// <param name="bytesToEncrypt">
        /// The byte array that will get encrypted.
        /// </param>
        /// <param name="nonce">
        /// The "number used only once" used during encryption.
        /// </param>
        /// <param name="key">The key used during encryption.</param>
        /// <param name="tag">The tag generated during encryption.</param>
        public static void AESCCMEncryptBytes(
            byte[] bytesToEncrypt, 
            byte[] nonce, 
            byte[] key,
            byte[] tag)
        {
            // Note that this passes the bytesToEncrypt as both the input and output array.
            // This works, since AES-CTR XOR-s the input array with the encrypted counters,
            // so this is equivalent to saying bytesToEncrypt[i + j] ^= encryptedCounter[j]
            using AesCcm ccm = new AesCcm(key);
            ccm.Encrypt(nonce, bytesToEncrypt, bytesToEncrypt, tag);
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
        /// The "cryptographic salt" used to derive the key, the SSID in the case of WPA2.
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

                // The salt value is padded with 4 bytes for the counter in the constructor
                byte[] saltValue = new byte[salt.Length + sizeof(uint)];
                salt.CopyTo(saltValue, 0);

                // Set the field value
                saltFieldInfo.SetValue(encryptor, saltValue);

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
            const int hashLength = 20;

            byte[] resultBytes = new byte[(int)n];
            byte[] argumentBytes = new byte[specificText.Length + 1 + specificData.Length + 1];
            byte[] hashResult;

            specificText.CopyTo(argumentBytes, 0);
            specificData.CopyTo(argumentBytes, specificText.Length + 1);

            using HMACSHA1 sha1 = new HMACSHA1(secretKey);
            // Integer division rounds towards zero, so this will omit any partial block at the end
            for (byte i = 0; i < resultBytes.Length / hashLength; i++)
            {
                argumentBytes[^1] = i;
                hashResult = sha1.ComputeHash(argumentBytes);
                hashResult.CopyTo(resultBytes, i * hashLength);
            }
            // Note that since n will never be a multiple of 20, there is no need to check
            // if the last block length is zero
            int lastBlockLengthInBytes = resultBytes.Length % hashLength;

            argumentBytes[^1]++;
            hashResult = sha1.ComputeHash(argumentBytes);
            Array.Copy(
                hashResult, 0, 
                resultBytes, resultBytes.Length - lastBlockLengthInBytes, 
                lastBlockLengthInBytes);

            return resultBytes;
        }
    }
}
