using PacketDotNet;
using System;
using System.Collections.Generic;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using WiFiMonitorClassLibrary.DataTypes;

namespace WiFiMonitorClassLibrary
{
    /// <summary>
    /// A class for monitoring WiFi communications.
    /// </summary>
    public class WiFiMonitor : IDisposable
    {
        private readonly int _readTimeout;

        private bool _capturing = false;

        public delegate void PacketArrivedEventHandler(object source, PacketArrivedEventArgs e);
        public event PacketArrivedEventHandler PacketArrived;

        /// <summary>
        /// Creates a new instance of WiFiMonitor.
        /// </summary>
        /// <param name="readTimeout">The timeout for reading packets.</param>
        public WiFiMonitor(int readTimeout = 1000)
        {
            _readTimeout = readTimeout;
        }

        public CaptureDeviceList CaptureDevices { get; private set; }
        public List<Packet> CapturedPackets { get; private set; } = new List<Packet>();

        /// <summary>
        /// Begins capturing WiFi packets on all devices available at the time of method call.
        /// </summary>
        public void BeginCapture()
        {
            if (_capturing)
            {
                EndCapture();
            }

            CaptureDevices = CaptureDeviceList.Instance;

            for (int i = 0; i < CaptureDevices.Count; i++)
            {
                try 
                {
                    StartCaptureOnDevice(CaptureDevices[i]);
                }
                catch { }
            }

            _capturing = true;
        }
        /// <summary>
        /// Ends capturing packets on all devices that were previously used for capturing.
        /// </summary>
        public void EndCapture()
        {
            if (CaptureDevices != null)
            {
                for (int i = 0; i < CaptureDevices.Count; i++)
                {
                    StopCaptureOnDevice(CaptureDevices[i]);
                }
            }

            CaptureDevices = null;
            _capturing = false;
        }

        /// <summary>
        /// The event handler for when a packet gets captured.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void HandlePacketArrival(object sender, CaptureEventArgs e)
        {
            Packet packet;
            try
            {
                // This will throw NotImplementedException if the packet has 
                // unsupported LinkLayerType
                packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            } 
            catch
            {
                // The packet captured may have all manner of things wrong with it, 
                // in which case the program should just ignore it
                return;
            }

            CapturedPackets.Add(packet);
            PacketArrived(this, new PacketArrivedEventArgs(packet));
        }
        /// <summary>
        /// Start capturing packets on the given device.
        /// </summary>
        /// <param name="device">The device on which to start capturing packets.</param>
        private void StartCaptureOnDevice(ICaptureDevice device)
        {
            // The following code is taken and modified from SharpPcap's Github repository's 
            // example 'BasicCap'
            // https://github.com/chmorgan/sharppcap/blob/master/Examples/Example3.BasicCap/Program.cs

            device.OnPacketArrival += HandlePacketArrival;

            // Open the device for capturing
            if (device is NpcapDevice)
            {
                var nPcap = device as NpcapDevice;
                // nPcap.Open(OpenFlags.DataTransferUdp | OpenFlags.NoCaptureLocal, _readTimeout);
                nPcap.Open(OpenFlags.Promiscuous, _readTimeout);
            }
            else if (device is LibPcapLiveDevice)
            {
                var livePcapDevice = device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous, _readTimeout, MonitorMode.Active);
            }
            else
            {
                throw new InvalidOperationException($"Unknown device type of {device.GetType()}");
            }

            // Start the capturing proccess
            device.StartCapture();
        }
        /// <summary>
        /// Stops capturing packets on the given device.
        /// </summary>
        /// <param name="device">The device on which to stop capturing packets.</param>
        private void StopCaptureOnDevice(ICaptureDevice device)
        {
            device.StopCapture();
        }
        /// <summary>
        /// Ends capturing.
        /// </summary>
        public void Dispose()
        {
            EndCapture();
        }
    }
}
