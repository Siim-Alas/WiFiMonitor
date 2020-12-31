using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using WiFiMonitorClassLibrary.Monitoring;

namespace WiFiMonitorClassLibrary
{
    /// <summary>
    /// A class for monitoring WiFi communications.
    /// </summary>
    public class WiFiMonitor : IDisposable
    {
        private readonly NetworkGraph _networkGraph;
        private readonly int _readTimeout;

        private CaptureDeviceList _captureDevices;
        private bool _capturing = false;

        public delegate void PacketArrivedEventHandler(object source, PacketArrivedEventArgs e);
        public event PacketArrivedEventHandler PacketArrived;

        /// <summary>
        /// Creates a new instance of WiFiMonitor.
        /// </summary>
        /// <param name="readTimeout">The timeout for reading packets.</param>
        /// <param name="constructNetworkGraph">
        /// If set to true, a graph of the network will be constructed, allowing for
        /// the capturing of Nonces, which can in turn be used for decrypting
        /// IEEE 802.11 data frames.
        /// </param>
        public WiFiMonitor(int readTimeout = 1000, bool constructNetworkGraph = false)
        {
            _readTimeout = readTimeout;

            if (constructNetworkGraph)
            {
                _networkGraph = new NetworkGraph();
                PacketArrived += _networkGraph.HandlePacketArrived;
            }
        }

        public List<Packet> CapturedPackets { get; private set; } = new List<Packet>();
        public NetworkGraph NetworkGraph 
        {
            get { return _networkGraph; }
        }
        /// <summary>
        /// Begins capturing WiFi packets on all devices available at the time of method call.
        /// </summary>
        public void BeginCapture()
        {
            if (_capturing)
            {
                EndCapture();
            }

            _captureDevices = CaptureDeviceList.Instance;

            for (int i = 0; i < _captureDevices.Count; i++)
            {
                try 
                {
                    // This might cause an exception due to lack of permission
                    StartCaptureOnDevice(_captureDevices[i]);
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
            if (_captureDevices != null)
            {
                for (int i = 0; i < _captureDevices.Count; i++)
                {
                    StopCaptureOnDevice(_captureDevices[i]);
                }
            }

            _captureDevices = null;
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
            device.OnPacketArrival -= HandlePacketArrival;
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
