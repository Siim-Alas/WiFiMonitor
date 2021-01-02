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
            /*
            string plainText = "Hello world!";
            byte[] sampleBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] bssid = new byte[6] { 1, 2, 3, 4, 5, 6 };
            string pwd = "password";

            byte[] maca = new byte[6] { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };
            byte[] macb = new byte[6] { 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f };

            byte[] noncea = new byte[] { 1, 2, 3, 4, 5, 6, 6, 4, 3, 2, 45 };
            byte[] nonceb = new byte[] { 3, 5, 2, 5, 6, 75, 26, 166, 4, 3, 5 };

            byte[] pmk = WPA2CryptographyTools.GeneratePairwiseMasterKey(bssid, pwd);
            byte[] ptk = WPA2CryptographyTools.GeneratePairwiseTransientKey(
                pmk, maca, macb, noncea, nonceb);

            byte[] encrKey = ptk[32..48];
            byte[] nonce = WPA2CryptographyTools.Generate104BitNonce(0, noncea, new byte[6]);
            byte[] initialCounter = WPA2CryptographyTools.GenerateCCMPInitialCounter(nonce);

            CryptographyWrapper.AESCounterModeEncryptBytes(sampleBytes, encrKey, initialCounter);
            Console.WriteLine(Encoding.UTF8.GetString(sampleBytes));

            CryptographyWrapper.AESCounterModeEncryptBytes(sampleBytes, encrKey, initialCounter);
            Console.WriteLine(Encoding.UTF8.GetString(sampleBytes));
            */
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
                    dataFrame, station.PairwiseTransientKey);
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
        }
    }
}
