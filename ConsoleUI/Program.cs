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
            byte[] bytesToDecrypt = new byte[100];
            byte[] counterBlock = new byte[128 / 8];
            byte[] key = new byte[128 / 8];

            byte[] encryptedBytes = 
                CryptographyWrapper.AESCounterModeEncryptBytes(bytesToDecrypt, key, counterBlock);
            byte[] decryptedBytes = 
                CryptographyWrapper.AESCounterModeEncryptBytes(encryptedBytes, key, counterBlock);
            Console.WriteLine(decryptedBytes.Length);
            for (int i = 0; i < decryptedBytes.Length; i++)
            {
                Console.WriteLine($"{i}) {decryptedBytes[i]}");
            }
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

                byte[] decryptedBytes = WPA2CryptographyTools.CCMPDecryptDataFrame(
                    dataFrame, station.PairwiseTransientKey);
                string decodedText = Encoding.GetEncoding("iso-8859-1").GetString(decryptedBytes);

                Console.WriteLine(decodedText);
            };

            Console.WriteLine("Access point password:");
            string password = Console.ReadLine();

            Console.WriteLine("Adding PMK.");
            wiFiMonitor.NetworkGraph.AddPassword("00-00-00-00-00-00", password);
            wiFiMonitor.NetworkGraph.AddPassword("00-00-00-00-00-00", password);
            wiFiMonitor.NetworkGraph.AddPassword("00-00-00-00-00-00", password);

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
