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
            using WiFiMonitor wiFiMonitor = new WiFiMonitor();
            wiFiMonitor.PacketArrived += (object sender, PacketArrivedEventArgs e) => 
            {
                if (e.ArrivedPacket is MacFrame)
                {
                    MacFrame macFrame = e.ArrivedPacket as MacFrame;
                    Console.WriteLine($"\n\n{macFrame}");
                    Console.WriteLine($"Frame size: {macFrame.FrameSize}");
                    Console.WriteLine($"FCS valid: {macFrame.FcsValid}");
                }
                else
                {
                    Console.WriteLine(e.ArrivedPacket?.GetType());
                }
            };
            wiFiMonitor.BeginCapture();

            Console.WriteLine($"Capturing on {wiFiMonitor.CaptureDevices.Count} devices:");

            for (int i = 0; i < wiFiMonitor.CaptureDevices.Count; i++)
            {
                Console.WriteLine(
                    $"{i + 1}) {wiFiMonitor.CaptureDevices[i].Name} -- {wiFiMonitor.CaptureDevices[i].Description}");
                Console.WriteLine($"Link layer type: {wiFiMonitor.CaptureDevices[i].LinkType}");
            }

            Console.ReadLine();
        }
    }
}
