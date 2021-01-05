using Microsoft.VisualStudio.TestTools.UnitTesting;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using WiFiMonitorClassLibrary.Parsing;

namespace WiFiMonitorClassLibraryUnitTests.Parsing
{
    [TestClass]
    public class FrameParserUnitTests
    {
        // 4-way handshake frames taken from https://github.com/mfontanini/libtins/blob/master/tests/src/wpa2_decrypt_test.cpp
        private readonly static byte[][] _4WHSFrames = new byte[][]
        {
            new byte[] {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 39, 0, 0, 183, 8, 75, 112, 8, 2, 44, 0, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 0, 12, 65, 130, 178, 85, 176, 252, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 117, 2, 0, 138, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 62, 142, 150, 125, 172, 217, 96, 50, 76, 172, 91, 106, 167, 33, 35, 91, 245, 123, 148, 151, 113, 200, 103, 152, 159, 73, 208, 78, 212, 124, 105, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 221, 20, 0, 15, 172, 4, 89, 45, 168, 128, 150, 196, 97, 218, 36, 108, 105, 0, 30, 135, 127, 61, 183, 8, 75, 112},
            new byte[] {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 56, 0, 0, 138, 11, 46, 247, 8, 1, 44, 0, 0, 12, 65, 130, 178, 85, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 144, 1, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 117, 2, 1, 10, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 205, 244, 5, 206, 185, 216, 137, 239, 61, 236, 66, 96, 152, 40, 250, 229, 70, 183, 173, 215, 186, 236, 187, 26, 57, 78, 172, 82, 20, 177, 211, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 164, 98, 167, 2, 154, 213, 186, 48, 182, 175, 13, 243, 145, 152, 142, 69, 0, 22, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0, 138, 11, 46, 247},
            new byte[] {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 40, 0, 0, 108, 57, 145, 12, 8, 2, 44, 0, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 0, 12, 65, 130, 178, 85, 192, 252, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 175, 2, 19, 202, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 62, 142, 150, 125, 172, 217, 96, 50, 76, 172, 91, 106, 167, 33, 35, 91, 245, 123, 148, 151, 113, 200, 103, 152, 159, 73, 208, 78, 212, 124, 105, 51, 245, 123, 148, 151, 113, 200, 103, 152, 159, 73, 208, 78, 212, 124, 105, 52, 207, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 125, 10, 246, 223, 81, 233, 156, 222, 122, 24, 116, 83, 240, 249, 53, 55, 0, 80, 207, 167, 44, 222, 53, 178, 193, 226, 49, 146, 85, 128, 106, 179, 100, 23, 159, 217, 103, 48, 65, 185, 165, 147, 159, 161, 162, 1, 13, 42, 199, 148, 226, 81, 104, 5, 95, 121, 77, 220, 31, 223, 174, 53, 33, 244, 68, 107, 253, 17, 218, 152, 52, 95, 84, 61, 246, 206, 25, 157, 248, 254, 72, 248, 205, 209, 122, 220, 168, 123, 244, 87, 17, 24, 60, 73, 109, 65, 170, 12, 108, 57, 145, 12},
            new byte[] {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 56, 0, 0, 239, 69, 111, 112, 8, 1, 44, 0, 0, 12, 65, 130, 178, 85, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 160, 1, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 95, 2, 3, 10, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 187, 163, 189, 251, 207, 222, 43, 197, 55, 80, 157, 113, 242, 236, 209, 0, 0, 239, 69, 111, 112},
        };
        private readonly DataFrame[] _4WHSDataFrames = new DataFrame[]
        {
            Packet.ParsePacket(LinkLayers.Ieee80211, _4WHSFrames[0]).Extract<DataFrame>(),
            Packet.ParsePacket(LinkLayers.Ieee80211, _4WHSFrames[1]).Extract<DataFrame>(),
            Packet.ParsePacket(LinkLayers.Ieee80211, _4WHSFrames[2]).Extract<DataFrame>(),
            Packet.ParsePacket(LinkLayers.Ieee80211, _4WHSFrames[3]).Extract<DataFrame>()
        };

        [DataTestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        public void TryToParse4WayHandshake_WithValidInput_ShouldReturnCorrect4WHSNumber(int i)
        {
            // Arrange and Act
            int handshakeNum = FrameParser.TryToParse4WayHandshake(
                _4WHSDataFrames[i], out EAPOLKeyFormat _);

            // Assert
            Assert.AreEqual(i + 1, handshakeNum);
        }
        [DataTestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        public void TryToParse4WayHandshake_WithValidInput_ShouldGiveNonNullEAPOLKeyFormat(int i)
        {
            // Arrange and Act
            FrameParser.TryToParse4WayHandshake(_4WHSDataFrames[i], out EAPOLKeyFormat keyFormat);

            // Assert
            Assert.IsNotNull(keyFormat);
        }
    }
}