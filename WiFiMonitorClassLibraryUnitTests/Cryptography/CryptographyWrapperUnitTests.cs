using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using WiFiMonitorClassLibrary.Cryptography;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibraryUnitTests.Cryptography
{
    [TestClass]
    public class CryptographyWrapperUnitTests
    {
        // AES-CCM test vectors from RFC 3610 https://tools.ietf.org/html/rfc3610
        // From Packet Vector 1
        private readonly byte[] _nonce = new byte[13]
        {
            0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5
        };
        private readonly byte[] _ctrKey = new byte[128 / 8]
        {
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 
            0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
        };
        private readonly byte[] _plaintext = new byte[]
        {
            // Removed 8-byte header
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
        };
        private readonly byte[] _ciphertext = new byte[]
        {
            // Removed 8-byte header
            0x58, 0x8C, 0x97, 0x9A, 0x61, 0xC6, 0x63, 0xD2,
            0xF0, 0x66, 0xD0, 0xC2, 0xC0, 0xF9, 0x89, 0x80, 
            0x6D, 0x5F, 0x6B, 0x61, 0xDA, 0xC3, 0x84
            // Removed 8-byte tag
        };
        private readonly byte[] _tag = new byte[8]
        {
            0x2D, 0xC6, 0x97, 0xE4, 0x11, 0xCA, 0x83, 0xA8
        };

        // PBKDF2 HMAC-SHA1 test vectors taken from https://tools.ietf.org/html/rfc6070
        private readonly byte[] _password = Encoding.ASCII.GetBytes("password");
        private readonly byte[] _salt = Encoding.ASCII.GetBytes("salt");
        private const int _iterations = 4096;
        private const int _dkLen = 20;
        private readonly byte[] _derivedKey = new byte[_dkLen]
        {
            0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
            0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
            0x65, 0xa4, 0x29, 0xc1
        };

        // IEEE 802.11TGi test vectors from https://mentor.ieee.org/802.11/dcn/02/11-02-0362-03-000i-proposed-test-vectors-for-ieee-802-11-tgi.doc
        // Test_case 4
        private readonly byte[] _prfKey = new byte[20]
        {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b
        };
        private readonly byte[] _prefix = Encoding.ASCII.GetBytes("prefix-4");
        private readonly byte[] _data = Encoding.ASCII.GetBytes("Hi There Again");
        private const CryptographyWrapper.PRFBitValues _length = CryptographyWrapper.PRFBitValues.bit512;
        private readonly byte[] _prf512 = new byte[(int)_length]
        {
            0x24, 0x8c, 0xfb, 0xc5, 0x32, 0xab, 0x38, 0xff, 
            0xa4, 0x83, 0xc8, 0xa2, 0xe4, 0x0b, 0xf1, 0x70, 
            0xeb, 0x54, 0x2a, 0x2e, 0xe4, 0xae, 0x63, 0x99, 
            0xa5, 0x52, 0xeb, 0x42, 0x39, 0x67, 0xda, 0x7f, 
            0x9d, 0x5b, 0xa7, 0xcb, 0xd6, 0x8e, 0x07, 0xa3, 
            0x5f, 0xaf, 0x13, 0x22, 0xf1, 0xcb, 0xc3, 0x5e,
            0x9a, 0x17, 0xed, 0xd6, 0x07, 0x78, 0x94, 0x30,
            0x15, 0x93, 0x71, 0xf4, 0x5e, 0xb1, 0xbc, 0xb6
        };

        [TestMethod]
        public void AESCCMEncryptBytes_WithValidCCMPInput_ShouldDecryptCorrectly()
        {
            // Arrange
            byte[] bytesToDecrypt = new byte[_ciphertext.Length];
            _ciphertext.CopyTo(bytesToDecrypt, 0);

            // Act
            CryptographyWrapper.AESCCMEncryptBytes(bytesToDecrypt, _nonce, _ctrKey, new byte[8]);
            bool decryptedCorrectly = 
                HelperMethods.CompareBuffers(_plaintext, bytesToDecrypt, _plaintext.Length) == 0;

            // Assert
            Assert.IsTrue(decryptedCorrectly);
        }
        [TestMethod]
        public void AESCCMEncryptBytes_WithValidCCMPInput_ShouldEncryptCorrectly()
        {
            // Arrange
            byte[] bytesToEncrypt = new byte[_plaintext.Length];
            _plaintext.CopyTo(bytesToEncrypt, 0);

            // Act
            CryptographyWrapper.AESCCMEncryptBytes(bytesToEncrypt, _nonce, _ctrKey, new byte[8]);
            bool encryptedCorrectly = 
                HelperMethods.CompareBuffers(_ciphertext, bytesToEncrypt, _ciphertext.Length) == 0;

            // Assert
            Assert.IsTrue(encryptedCorrectly);
        }
        [TestMethod]
        public void AESCCMEncryptBytes_WithValidCCMPInput_ShouldProduceCorrectTag()
        {
            // Arrange
            byte[] bytesToEncrypt = new byte[_plaintext.Length];
            _plaintext.CopyTo(bytesToEncrypt, 0);
            byte[] tag = new byte[_tag.Length];

            // Act
            CryptographyWrapper.AESCCMEncryptBytes(bytesToEncrypt, _nonce, _ctrKey, tag);
            bool tagIsCorrect = HelperMethods.CompareBuffers(_tag, tag, _tag.Length) == 0;

            // Assert
            Assert.IsTrue(tagIsCorrect);
        }
        [TestMethod]
        public void PBKDF2_WithValidInput_ShouldReturnCorrectKey()
        {
            // Arrange and Act
            byte[] derivedKey = 
                CryptographyWrapper.PBKDF2(_password, _salt, _iterations, _dkLen);
            bool deriveKeyIsCorrect = 
                HelperMethods.CompareBuffers(derivedKey, _derivedKey, _dkLen) == 0;

            // Assert
            Assert.IsTrue(deriveKeyIsCorrect);
        }
        [TestMethod]
        public void PRFn_WithValidInput_ShouldReturnByteArrayWithCorrectLength()
        {
            // Arrange and Act
            byte[] resultBytes = 
                CryptographyWrapper.PRFn(_length, _prfKey, _prefix, _data);

            // Assert
            Assert.AreEqual((int)_length, resultBytes.Length);
        }
        [TestMethod]
        public void PRFn_WithValidInput_ShouldReturnCorrectBytes()
        {
            // Arrange and Act
            byte[] resultBytes = 
                CryptographyWrapper.PRFn(_length, _prfKey, _prefix, _data);
            bool resultIsCorrect = 
                HelperMethods.CompareBuffers(resultBytes, _prf512, (int)_length) == 0;

            // Assert
            Assert.IsTrue(resultIsCorrect);
        }
    }
}
