using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using WiFiMonitorClassLibrary.Cryptography;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibraryUnitTests.Cryptography
{
    [TestClass]
    public class CryptographyWrapperUnitTests
    {
        // AES-CTR test vectors taken from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        // F.5.1 CTR-AES128.Encrypt (from the link)
        private readonly byte[] _initialCounter = new byte[128 / 8]
        {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
        };
        private readonly byte[] _ctrKey = new byte[128 / 8]
        {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        private readonly byte[] _plaintext = new byte[4 * (128 / 8)]
        {
            // Block #1
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            // Block #2
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            // Block #3
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            // Block #4
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
        };
        private readonly byte[] _ciphertext = new byte[4 * (128 / 8)]
        {
            // Block #1
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 
            0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
            // Block #2
            0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 
            0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
            // Block #3
            0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 
            0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
            // Block #4
            0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 
            0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
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
        public void AESCounterModeEncryptBytes_WithValidInputOfLengthDividibleByBlockSize_EncryptingTwiceShouldResultInNoChange()
        {
            // Arrange
            byte[] testBytes = new byte[_plaintext.Length];
            _plaintext.CopyTo(testBytes, 0);

            // Act
            CryptographyWrapper.AESCounterModeEncryptBytes(testBytes, _initialCounter, _ctrKey);
            CryptographyWrapper.AESCounterModeEncryptBytes(testBytes, _initialCounter, _ctrKey);

            bool testBytesEqualPlainText = 
                HelperMethods.CompareBuffers(_plaintext, testBytes, _plaintext.Length) == 0;

            // Assert
            Assert.IsTrue(testBytesEqualPlainText);
        }
        [TestMethod]
        public void AESCounterModeEncryptBytes_WithValidInputOfLengthDividibleByBlockSize_ShouldEncryptCorrectly()
        {
            // Arrange
            byte[] testBytes = new byte[_plaintext.Length];
            _plaintext.CopyTo(testBytes, 0);

            // Act
            CryptographyWrapper.AESCounterModeEncryptBytes(testBytes, _initialCounter, _ctrKey);

            bool testBytesEqualCipherText =
                HelperMethods.CompareBuffers(_ciphertext, testBytes, _ciphertext.Length) == 0;

            // Assert
            Assert.IsTrue(testBytesEqualCipherText);
        }
        [TestMethod]
        public void AESCounterModeEncryptBytes_WithValidInputOfLengthIndvidibleByBlockSize_EncryptingTwiceShouldResultInNoChange()
        {
            // Arrange
            int length = _plaintext.Length - 3;

            byte[] testBytes = new byte[length];
            _plaintext[0..length].CopyTo(testBytes, 0);

            // Act
            CryptographyWrapper.AESCounterModeEncryptBytes(testBytes, _initialCounter, _ctrKey);
            CryptographyWrapper.AESCounterModeEncryptBytes(testBytes, _initialCounter, _ctrKey);

            bool testBytesEqualPlainText =
                HelperMethods.CompareBuffers(_plaintext, testBytes, length) == 0;

            // Assert
            Assert.IsTrue(testBytesEqualPlainText);
        }
        [TestMethod]
        public void AESCounterModeEncryptBytes_WithValidInputOfLengthIndividibleByBlockSize_ShouldEncryptCorrectly()
        {
            // Arrange
            int length = _plaintext.Length - 3;

            byte[] testBytes = new byte[length];
            _plaintext[0..length].CopyTo(testBytes, 0);

            // Act
            CryptographyWrapper.AESCounterModeEncryptBytes(testBytes, _initialCounter, _ctrKey);

            bool testBytesEqualCipherText =
                HelperMethods.CompareBuffers(_ciphertext, testBytes, length) == 0;

            // Assert
            Assert.IsTrue(testBytesEqualCipherText);
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
            bool resultLengthIsCorrect = resultBytes.Length == (int)_length;

            // Assert
            Assert.IsTrue(resultLengthIsCorrect);
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
