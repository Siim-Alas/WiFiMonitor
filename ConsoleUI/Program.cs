using PacketDotNet;
using PacketDotNet.Ieee80211;
using System;
using System.Net.NetworkInformation;
using System.Text;
using WiFiMonitorClassLibrary;
using WiFiMonitorClassLibrary.Cryptography;
using WiFiMonitorClassLibrary.Monitoring;

namespace ConsoleUI
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] _tk8 = new byte[16]
            {
                0x6e, 0xac, 0x1b, 0xf5, 0x4b, 0xd5, 0x4e, 0xdb,
                0x23, 0x21, 0x75, 0x43, 0x03, 0x02, 0x4c, 0x71
            };
            byte[] _plaintextData8 = new byte[]
            {
                0x57, 0xcb, 0x5c, 0x0e, 0x5f, 0xcd, 0x88, 0x5e, 
                0x9a, 0x42, 0x39, 0xe9, 0xb9, 0xca, 0xd6, 0x0d, 
                0x64, 0x37, 0x59, 0x79
            };
            byte[] _ciphertextMPDU8 = new byte[]
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

            // Arrange
            // Packet encryptedPacket = Packet.ParsePacket(LinkLayers.Ieee80211, _ciphertextMPDU);
            Packet encryptedPacket = MacFrame.ParsePacketWithFcs(
                new PacketDotNet.Utils.ByteArraySegment(_ciphertextMPDU8));
            DataFrame encryptedDataFrame = encryptedPacket.Extract<DataFrame>();

            // Act
            byte[] actualDecryptedBody = 
                WPA2CryptographyTools.CCMPTryDecryptDataFrame(encryptedDataFrame, _tk8);
            bool decryptedCorrectly = WiFiMonitorClassLibrary.StaticHelpers.HelperMethods.CompareBuffers(
                _plaintextData8, actualDecryptedBody, _plaintextData8.Length) == 0;
            Console.WriteLine(encryptedDataFrame.FcsValid);
            Console.WriteLine(decryptedCorrectly);

            /*
            using WiFiMonitor wiFiMonitor = new WiFiMonitor(constructNetworkGraph: true);
            wiFiMonitor.PacketArrived += (object sender, PacketArrivedEventArgs e) => 
            {
                DataFrame dataFrame = e.ArrivedPacket.Extract<DataFrame>();
                if (dataFrame?.PayloadData == null)
                {
                    return;
                }

                wiFiMonitor.NetworkGraph.GetDestinationAndSource(
                    dataFrame, out AccessPoint accessPoint, out Station station);

                if (station.PairwiseTransientKey == null)
                {
                    return;
                }

                Console.WriteLine("Attempting to decrypt");

                byte[] decryptedBytes = WPA2CryptographyTools.CCMPTryDecryptDataFrame(
                    dataFrame, station.PairwiseTransientKey[32..48]);
                string decodedText = Encoding.GetEncoding("iso-8859-1").GetString(decryptedBytes);

                Console.WriteLine(decodedText);
            };

            Console.WriteLine("Access point password:");
            string password = Console.ReadLine();

            Console.WriteLine("Adding PMK.");
            wiFiMonitor.NetworkGraph.AddPassword(
                "00-00-00-00-00-00", "<ssid>", password);
            wiFiMonitor.NetworkGraph.AddPassword(
                "00-00-00-00-00-00", "<ssid>", password);
            wiFiMonitor.NetworkGraph.AddPassword(
                "00-00-00-00-00-00", "<ssid>", password);

            Console.WriteLine("Beginning capture.");
            wiFiMonitor.BeginCapture();
            Console.WriteLine("Capturing, press any key to stop...\n\n");

            Console.ReadKey();
            Console.WriteLine("\n\nEnding capture.");
            Console.WriteLine("Disposing WiFiMonitor.");
            wiFiMonitor.Dispose();
            Console.WriteLine("WifiMonitor disposed, terminating.");
            */
        }
    }
}
