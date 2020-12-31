using PacketDotNet;
using PacketDotNet.Ieee80211;
using System;
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

                Console.WriteLine("Data frame with non-null data");

                bool accessPointIsDestination = 
                    wiFiMonitor.NetworkGraph.GetDestinationAndSource(
                        dataFrame, out AccessPoint accessPoint, out Station station);
                if (station.PairwiseTemporalKey == null)
                {
                    return;
                }

                Console.WriteLine("Attempting to decrypt");

                byte[] decryptedBytes = WPA2CryptographyTools.CCMPDecryptDataFrame(
                    dataFrame, station.PairwiseTemporalKey);
                string decodedText = Encoding.UTF8.GetString(decryptedBytes);

                Console.WriteLine(decodedText);
            };

            Console.WriteLine("Access point BSSID:");
            string bssid = Console.ReadLine();
            Console.WriteLine("Access point password:");
            string password = Console.ReadLine();

            Console.WriteLine("Adding PMK.");
            wiFiMonitor.NetworkGraph.AddPassword(bssid, password);

            Console.WriteLine("Beginning capture.");
            wiFiMonitor.BeginCapture();
            Console.WriteLine("Capturing, press any key to stop...\n\n");

            Console.ReadKey();
            Console.WriteLine("\n\nEnding capture.");
            wiFiMonitor.Dispose();
            Console.WriteLine("WifiMonitor disposed, terminating.");
        }
    }
}
