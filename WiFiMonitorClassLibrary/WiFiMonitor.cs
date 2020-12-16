using System;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;

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
        /// Creates a new instance of WiFiMonitor
        /// </summary>
        /// <param name="readTimeout">The timeout for reading packets.</param>
        public WiFiMonitor(int readTimeout = 1000)
        {
            _readTimeout = readTimeout;
        }

        public CaptureDeviceList CaptureDevices { get; private set; }

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
                StartCaptureOnDevice(CaptureDevices[i]);
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
            PacketArrived?.Invoke(this, new PacketArrivedEventArgs($"{e.Device.Description} captured {e.Packet}"));
        }
        /// <summary>
        /// Start capturing packets on the given device.
        /// </summary>
        /// <param name="device">The device on which to start capturing packets.</param>
        private void StartCaptureOnDevice(ICaptureDevice device)
        {
            // The following code is taken and modified from SharpPcap's Github repository's example 'BasicCap'
            // https://github.com/chmorgan/sharppcap/blob/master/Examples/Example3.BasicCap/Program.cs

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += HandlePacketArrival;

            // Open the device for capturing
            if (device is NpcapDevice)
            {
                var nPcap = device as NpcapDevice;
                nPcap.Open(OpenFlags.DataTransferUdp | OpenFlags.NoCaptureLocal, _readTimeout);
            }
            else if (device is LibPcapLiveDevice)
            {
                var livePcapDevice = device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous, _readTimeout);
            }
            else
            {
                throw new InvalidOperationException($"Unknown device type of {device.GetType()}");
            }

            // Actually start the capturing proccess
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
