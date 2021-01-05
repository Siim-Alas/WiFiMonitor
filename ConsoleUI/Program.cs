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
                string decodedText = Encoding.UTF8.GetString(decryptedBytes);

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
