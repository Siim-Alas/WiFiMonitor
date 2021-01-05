using Microsoft.VisualStudio.TestTools.UnitTesting;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using WiFiMonitorClassLibrary.Parsing;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibraryUnitTests.Parsing
{
    [TestClass]
    public class CCMPHeaderUnitTests
    {
        // CCMP test vectors from https://web.mit.edu/freebsd/head/tools/regression/net80211/ccmp/test_ccmp.c
        // Test 6
        private readonly byte[] _headerBytes = new byte[8]
        {
            0x89, 0x89, 0x00, 0x60, 0xa4, 0xec, 0x81, 0x6b
        };
        private const int _keyID = 1;
        private readonly byte[] _packetNumber = new byte[6]
        {
            0x6B, 0x81, 0xEC, 0xA4, 0x89, 0x89
        };
        private readonly static byte[] _frameBytes = new byte[]
        {
            // MAC Header
            0x88, 0x52, 0xe1, 0x1f, 0x5a, 0xf2, 0x84, 0x30, 
            0xfd, 0xab, 0xbf, 0xf9, 0x43, 0xb9, 0xf9, 0xa6, 
            0xab, 0x1d, 0x98, 0xc7, 0xfe, 0x73, 0x50, 0x71, 
            0x3d, 0x6a, 
            // CCMP Header
            0x89, 0x89, 0x00, 0x60, 0xa4, 0xec, 0x81, 0x6b, 
            // Frame Body
            0x9a, 0x70, 0x9b, 0x60, 0xa3, 0x9d, 0x40, 0xb1, 
            0xdf, 0xb6, 0x12, 0xe1, 0x8b, 0x5f, 0x11, 0x4b,
            0xad, 0xb6, 0xcc, 0x86, 
            // MIC
            0x30, 0x9a, 0x8d, 0x5c, 0x46, 0x6b, 0xbb, 0x71,
            // FCS
            0x86, 0xc0, 0x4e, 0x97
        };
        private readonly static MacFrame _macFrame = 
            Packet.ParsePacket(LinkLayers.Ieee80211, _frameBytes).Extract<MacFrame>();
        private readonly CCMPHeader _ccmpHeader = new CCMPHeader(_macFrame);

        [TestMethod]
        public void Bytes_WithValidInput_ShouldHaveCorrectLength()
        {
            // Arrange and Act
            bool bytesFieldHasCorrectLength = _ccmpHeader.Bytes.Length == _headerBytes.Length;

            // Assert
            Assert.IsTrue(bytesFieldHasCorrectLength);
        }
        [TestMethod]
        public void Bytes_WithValidInput_ShouldHaveCorrectValue()
        {
            // Arrange and Act
            bool bytesFieldIsCorrect = HelperMethods.CompareBuffers(
                _ccmpHeader.Bytes, _headerBytes, _headerBytes.Length) == 0;

            // Assert
            Assert.IsTrue(bytesFieldIsCorrect);
        }
        [TestMethod]
        public void KeyID_WithValidInput_ShouldHaveCorrectValue()
        {
            // Assert
            Assert.AreEqual(_keyID, _ccmpHeader.KeyID);
        }
        [TestMethod]
        public void PacketNumber_WithValidInput_ShouldHaveCorrectLength()
        {
            // Assert
            Assert.AreEqual(_packetNumber.Length, _ccmpHeader.PacketNumber.Length);
        }
        [TestMethod]
        public void PacketNumber_WithValidInput_ShouldHaveCorrectValue()
        {
            // Arrange and Act
            bool packetNumberHasCorrectValue = HelperMethods.CompareBuffers(
                _ccmpHeader.PacketNumber, _packetNumber, _packetNumber.Length) == 0;

            // Assert
            Assert.IsTrue(packetNumberHasCorrectValue);
        }
    }
}