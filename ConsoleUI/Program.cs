using PacketDotNet;
using PacketDotNet.Ieee80211;
using System;
using System.Linq;
using WiFiMonitorClassLibrary;
using WiFiMonitorClassLibrary.DataTypes;

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
                else if (e.ArrivedPacket is LinuxSllPacket)
                {
                    LinuxSllPacket packet = e.ArrivedPacket as LinuxSllPacket;
                    if (packet.Type == LinuxSllType.PacketSentToSomeoneElse)
                    {
                        Console.WriteLine(packet.ToString());
                    }
                }
                else if (e.ArrivedPacket is RadioPacket)
                {
                    RadioPacket radioPacket = e.ArrivedPacket as RadioPacket;

                    if (radioPacket.PayloadPacket is DataFrame)
                    {
                        byte[] ipadMAC = new byte[] {
                            0x06, 0x7A, 0x70, 0x71, 0x73, 0xB5
                        };

                        DataFrame dataFrame = radioPacket.PayloadPacket as DataFrame;
                        bool isDest = Enumerable.SequenceEqual(
                            dataFrame.DestinationAddress.GetAddressBytes(), ipadMAC);
                        bool isSource = Enumerable.SequenceEqual(
                            dataFrame.SourceAddress.GetAddressBytes(), ipadMAC);

                        if (isDest || isSource)
                        {
                            Console.WriteLine(dataFrame.ToString());

                            EAPOLKeyFormat keyFormat = 
                                FrameParser.TryGetEAPOLKeyFromDataFrame(dataFrame);
                            
                            if (keyFormat != null)
                            {
                                Console.WriteLine("Success!!!");
                            }
                        }
                    }
                }
                else
                {
                    // Console.WriteLine(e.ArrivedPacket?.GetType());
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
