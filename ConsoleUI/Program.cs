using PacketDotNet;
using PacketDotNet.Ieee80211;
using System;
using WiFiMonitorClassLibrary;

namespace ConsoleUI
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            
            using WiFiMonitor wiFiMonitor = new WiFiMonitor();
            wiFiMonitor.PacketArrived += (object sender, PacketArrivedEventArgs e) => 
            {
                if (e.ArrivedPacket is MacFrame)
                {
                    MacFrame macFrame = e.ArrivedPacket as MacFrame;
                    Console.WriteLine($"Captured ieee802.11 packet of type {macFrame.FrameControl.Type}");
                }
                else
                {
                    Console.WriteLine(e.ArrivedPacket.GetType());
                }
            };
            wiFiMonitor.BeginCapture();

            Console.WriteLine($"Capturing on {wiFiMonitor.CaptureDevices.Count} devices:");

            for (int i = 0; i < wiFiMonitor.CaptureDevices.Count; i++)
            {
                Console.WriteLine(
                    $"{i + 1}) {wiFiMonitor.CaptureDevices[i].Name} -- {wiFiMonitor.CaptureDevices[i].Description}");
            }

            Console.ReadLine();
        }
    }
}
