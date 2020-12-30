using PacketDotNet;
using PacketDotNet.Ieee80211;
using System;
using WiFiMonitorClassLibrary;
using WiFiMonitorClassLibrary.Parsing;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace ConsoleUI
{
    class Program
    {
        static void Main(string[] args)
        {
            using WiFiMonitor wiFiMonitor = new WiFiMonitor(constructNetworkGraph: true);
            wiFiMonitor.PacketArrived += (object sender, PacketArrivedEventArgs e) => 
            {
                // Do something
            };
            wiFiMonitor.BeginCapture();

            Console.ReadLine();
        }
    }
}
