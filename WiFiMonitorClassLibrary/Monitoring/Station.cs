
namespace WiFiMonitorClassLibrary.Monitoring
{
    public class Station
    {
        public byte[] ANonce { get; set; }
        public byte[] PairwiseTransientKey { get; set; }
        public byte[] SNonce { get; set; }
    }
}