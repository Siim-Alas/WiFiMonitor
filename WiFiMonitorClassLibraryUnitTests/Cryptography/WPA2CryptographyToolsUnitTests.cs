using Microsoft.VisualStudio.TestTools.UnitTesting;
using WiFiMonitorClassLibrary.Cryptography;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibraryUnitTests.Cryptography
{
    [TestClass]
    public class WPA2CryptographyToolsUnitTests
    {
        // Pairwise Master Key test vector from the online Wireshark PMK generator at https://www.wireshark.org/tools/wpa-psk.html
        private const string _passphrase = "passphrase";
        private const string _ssid = "SSID that has a length between 8 and 63";
        private readonly byte[] _pmk1 = new byte[32]
        {
            0xdd, 0x5b, 0xab, 0xcb, 0x3a, 0x96, 0x92, 0xf9, 
            0xa1, 0xe3, 0x20, 0x72, 0x4e, 0x58, 0x59, 0xb9, 
            0x79, 0xbc, 0x52, 0x4a, 0xf4, 0x1f, 0x03, 0x39, 
            0xc0, 0x3c, 0xab, 0x9f, 0x69, 0x0a, 0x2e, 0xb5
        };

        // Key Hierarchy Test Vectors from https://mentor.ieee.org/802.11/dcn/02/11-02-0362-03-000i-proposed-test-vectors-for-ieee-802-11-tgi.doc
        // TODO: find a WPA2 test vector, this is for TKIP
        private readonly byte[] _pairwiseMasterKey = new byte[32]
        {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
        };
        private readonly byte[] _AA = new byte[6]
        {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };
        private readonly byte[] _SA = new byte[6]
        {
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02
        };
        private readonly byte[] _sNonce = new byte[20]
        {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01
        };
        private readonly byte[] _aNonce = new byte[20]
        {
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20
        };
        private readonly byte[] _pairwiseTransientKey = new byte[64]
        {
            // KCK
            0x86, 0xf5, 0x6f, 0xfd, 0x2d, 0xb9, 0x9b, 0xb8,
            0xe8, 0x72, 0x26, 0x09, 0x7b, 0x16, 0x0a, 0x42,
            // KEK
            0xeb, 0xff, 0x51, 0x15, 0xae, 0xaa, 0x72, 0xf1, 
            0xd7, 0xc0, 0x64, 0xe3, 0xc9, 0x4d, 0x7c, 0xf5,
            // TK
            0xef, 0x14, 0x31, 0xfb, 0x94, 0x8e, 0x99, 0x97, 
            0xde, 0x0f, 0x4f, 0x3d, 0x46, 0x37, 0xf0, 0xe9,
            // TK extensions for TKIP
            0x6d, 0xdd, 0xbc, 0xdb, 0xbd, 0x34, 0xab, 0x3f,
            0xa7, 0xde, 0xb3, 0x7c, 0x16, 0x85, 0xe0, 0x35
        };

        [TestMethod]
        public void GeneratePairwiseMasterKey_WithValidInput_ShouldGenerateCorrectKey()
        {
            // Arrange and Act
            byte[] pmk = 
                WPA2CryptographyTools.GeneratePairwiseMasterKey(_passphrase, _ssid);
            bool pmkIsCorrect = 
                HelperMethods.CompareBuffers(pmk, _pmk1, _pmk1.Length) == 0;

            // Assert
            Assert.IsTrue(pmkIsCorrect);
        }
        [TestMethod]
        public void GeneratePairwiseTransientKey_WithValidInput_ShouldGenerateCorrectKey()
        {
            // NB! The current version of the test relies on old TKIP 
            // test vectors
            // TODO: Find WPA2 test vectors

            // Arrange and Act
            byte[] ptk = WPA2CryptographyTools.GeneratePairwiseTransientKey(
                _pairwiseMasterKey, _AA, _SA, _sNonce, _aNonce);
            bool ptkIsCorrect = HelperMethods.CompareBuffers(
                ptk, _pairwiseTransientKey, 48) == 0;

            // Assert
            Assert.IsTrue(ptkIsCorrect);
        }
    }
}
