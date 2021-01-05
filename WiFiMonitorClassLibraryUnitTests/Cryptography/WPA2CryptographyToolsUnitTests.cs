using Microsoft.VisualStudio.TestTools.UnitTesting;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using WiFiMonitorClassLibrary.Cryptography;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibraryUnitTests.Cryptography
{
    [TestClass]
    public class WPA2CryptographyToolsUnitTests
    {
        // CCMP test vector from MIT https://web.mit.edu/freebsd/head/tools/regression/net80211/ccmp/test_ccmp.c
        // Test 1
        // Temporal Key
        private readonly byte[] _tk1 = new byte[16]
        {
            0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85, 
            0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f
        };
        private readonly byte[] _plaintextData1 = new byte[]
        {
            0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae,
            0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb,
            0x7e, 0x78, 0xa0, 0x50
        };
        private readonly byte[] _ciphertextMPDU1 = new byte[]
        {
            // MAC Header
            0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28,
            0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08,
            0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33,
            // CCMP Header
            0x0c, 0xe7, 0x00, 0x20, 0x76, 0x97, 0x03, 0xb5,
            // Frame body
            0xf3, 0xd0, 0xa2, 0xfe, 0x9a, 0x3d, 0xbf, 0x23,
            0x42, 0xa6, 0x43, 0xe4, 0x32, 0x46, 0xe8, 0x0c,
            0x3c, 0x04, 0xd0, 0x19, 
            // MIC
            0x78, 0x45, 0xce, 0x0b, 0x16, 0xf9, 0x76, 0x23, 
            // FCS
            0x1d, 0x99, 0xf0, 0x66
        };
        // Test 8
        private readonly byte[] _tk8 = new byte[16]
        {
            0x6e, 0xac, 0x1b, 0xf5, 0x4b, 0xd5, 0x4e, 0xdb,
	        0x23, 0x21, 0x75, 0x43, 0x03, 0x02, 0x4c, 0x71
        };
        private readonly byte[] _plaintextData8 = new byte[]
        {
            0x57, 0xcb, 0x5c, 0x0e, 0x5f, 0xcd, 0x88, 0x5e, 
            0x9a, 0x42, 0x39, 0xe9, 0xb9, 0xca, 0xd6, 0x0d, 
            0x64, 0x37, 0x59, 0x79
        };
        private readonly byte[] _ciphertextMPDU8 = new byte[]
        {
            // MAC Header
            0xb8, 0xd9, 0x4c, 0x72, 0x55, 0x2d, 0x5f, 0x72, 
            0xbb, 0x70, 0xca, 0x3f, 0x3a, 0xae, 0x60, 0xc4, 
            0x8b, 0xa9, 0xb5, 0xf8, 0x2c, 0x2f, 0x50, 0xeb, 
            0x2a, 0x55, 
            // CCMP Header
            0xdd, 0xcc, 0x00, 0xa0, 0x6e, 0x99, 0xfd, 0xce, 
            // Frame body
            0x4b, 0xf2, 0x81, 0xef, 0x8e, 0xc7, 0x73, 0x9f, 
            0x91, 0x59, 0x1b, 0x97, 0xa8, 0x7d, 0xc1, 0x4b,
            0x3f, 0xa1, 0x74, 0x62, 
            // MIC
            0x6d, 0xba, 0x8e, 0xf7, 0xf0, 0x80, 0x87, 0xdd,
            // FCS
            0x0c, 0x65, 0x74, 0x3f
        };
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
        public void CCMPTryDecryptDataFrame_WithValidInput1_ShouldDecryptCorrectly()
        {
            // Arrange
            Packet encryptedPacket = Packet.ParsePacket(LinkLayers.Ieee80211, _ciphertextMPDU1);
            DataFrame encryptedDataFrame = encryptedPacket.Extract<DataFrame>();

            // Act
            byte[] actualDecryptedBody = 
                WPA2CryptographyTools.CCMPTryDecryptDataFrame(encryptedDataFrame, _tk1);
            bool decryptedCorrectly = HelperMethods.CompareBuffers(
                _plaintextData1, actualDecryptedBody, _plaintextData1.Length) == 0;

            // Assert
            Assert.IsTrue(decryptedCorrectly);
        }
        [TestMethod]
        public void CCMPTryDecryptDataFrame_WithValidInput8_ShouldDecryptCorrectly()
        {
            // Arrange
            Packet encryptedPacket = Packet.ParsePacket(LinkLayers.Ieee80211, _ciphertextMPDU8);
            DataFrame encryptedDataFrame = encryptedPacket.Extract<DataFrame>();

            // Act
            byte[] actualDecryptedBody = 
                WPA2CryptographyTools.CCMPTryDecryptDataFrame(encryptedDataFrame, _tk8);
            bool decryptedCorrectly = HelperMethods.CompareBuffers(
                _plaintextData8, actualDecryptedBody, _plaintextData8.Length) == 0;

            // Assert
            Assert.IsTrue(decryptedCorrectly);
        }
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
