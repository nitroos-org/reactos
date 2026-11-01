// Clean-room DnsClient helper for ReactOS-Nitro: the DnsRecord object model of Resolve-DnsName and a dnsapi
// (DnsQuery_W) wrapper. Class, property and enum names follow the Windows module's public surface.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.DnsClient.Commands
{
    public class DnsRecord
    {
        public string Name;
        public RecordType Type;
        public DNSCharset CharacterSet;
        public DNSSection Section;
        public ushort DataLength;
        public uint TTL;
    }
    public class DnsRecord_A : DnsRecord { public string IP4Address; }
    public class DnsRecord_AAAA : DnsRecord { public string IP6Address; }
    public class DnsRecord_PTR : DnsRecord { public string NameHost; }
    public class DnsRecord_MX : DnsRecord { public string NameExchange; public ushort Preference; }
    public class DnsRecord_SOA : DnsRecord
    {
        public string PrimaryServer;
        public string NameAdministrator;
        public uint SerialNumber;
        public uint TimeToZoneRefresh;
        public uint TimeToZoneFailureRetry;
        public uint TimeToExpiration;
        public uint DefaultTTL;
    }
    public class DnsRecord_TXT : DnsRecord { public string[] Strings; }
    public class DnsRecord_SRV : DnsRecord
    {
        public string NameTarget;
        public ushort Priority;
        public ushort Weight;
        public ushort Port;
    }
    public class DnsRecord_Unknown : DnsRecord { public byte[] Data; }

    // Stand-in for the Windows cmdlet type: the ErrorRecords written by Resolve-DnsName are stamped as coming from it,
    // so FullyQualifiedErrorId reads "<error>,Microsoft.DnsClient.Commands.ResolveDnsName". Never registered as a command.
    [Cmdlet("Resolve", "DnsName")] public class ResolveDnsName : PSCmdlet { }

    // Outcome of a query: the records, or a non-zero Win32/DNS error code. Failures travel as values so that nothing
    // lands in $Error before Resolve-DnsName writes its own ErrorRecord.
    public sealed class DnsResult
    {
        public List<DnsRecord> Records = new List<DnsRecord>();
        public int Code;
    }

    public static class DnsNative
    {
        [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
        static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr servers, out IntPtr results, IntPtr reserved);
        [DllImport("dnsapi.dll")]
        static extern void DnsRecordListFree(IntPtr list, int freeType);

        static string Str(IntPtr p) { return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p); }

        public static string ErrorText(int code)
        {
            switch (code)
            {
                case 1460: return "This operation returned because the timeout period expired.";
                case 9001: return "DNS server unable to interpret format.";
                case 9002: return "DNS server failure.";
                case 9003: return "DNS name does not exist.";
                case 9004: return "DNS request not supported by name server.";
                case 9005: return "DNS operation refused.";
                case 9501: return "No records found for given DNS query.";
                case 9701: return "DNS record does not exist.";
            }
            return new Win32Exception(code).Message;
        }

        public static string ErrorName(int code)
        {
            switch (code)
            {
                case 1460: return "ERROR_TIMEOUT";
                case 9001: return "DNS_ERROR_RCODE_FORMAT_ERROR";
                case 9002: return "DNS_ERROR_RCODE_SERVER_FAILURE";
                case 9003: return "DNS_ERROR_RCODE_NAME_ERROR";
                case 9004: return "DNS_ERROR_RCODE_NOT_IMPLEMENTED";
                case 9005: return "DNS_ERROR_RCODE_REFUSED";
                case 9701: return "DNS_ERROR_RECORD_DOES_NOT_EXIST";
            }
            return code.ToString(CultureInfo.InvariantCulture);
        }

        public static Exception Failure(string name, int code) { return new Win32Exception(code, name + " : " + ErrorText(code)); }

        public static ErrorCategory ErrorCategoryOf(int code) { return code == 1460 ? ErrorCategory.OperationTimeout : ErrorCategory.ResourceUnavailable; }

        // Runs one DnsQuery_W and returns every record of the answer, authority and additional sections.
        // A query that succeeds with no records (DNS_INFO_NO_RECORDS) returns an empty list; other failures set Code.
        public static DnsResult Query(string name, ushort type, uint options, string[] servers)
        {
            DnsResult result = new DnsResult();
            List<DnsRecord> res = result.Records;
            IntPtr srv = IntPtr.Zero, list = IntPtr.Zero;
            try
            {
                if (servers != null && servers.Length > 0)
                {
                    List<byte[]> a4 = new List<byte[]>();
                    foreach (string s in servers)
                    {
                        IPAddress ip;
                        if (IPAddress.TryParse(s, out ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) a4.Add(ip.GetAddressBytes());
                    }
                    if (a4.Count > 0)
                    {
                        srv = Marshal.AllocHGlobal(4 + 4 * a4.Count);   // IP4_ARRAY
                        Marshal.WriteInt32(srv, a4.Count);
                        for (int i = 0; i < a4.Count; i++) Marshal.Copy(a4[i], 0, srv + 4 + 4 * i, 4);
                    }
                }
                int rc = DnsQuery_W(name, type, options, srv, out list, IntPtr.Zero);
                if (rc == 9501 || rc == 9701) return result;
                if (rc != 0) { result.Code = rc; return result; }
                int dataOff = IntPtr.Size == 8 ? 32 : 24;
                for (IntPtr p = list; p != IntPtr.Zero; )
                {
                    IntPtr next = Marshal.ReadIntPtr(p);
                    IntPtr pName = Marshal.ReadIntPtr(p, IntPtr.Size);
                    ushort rtype = (ushort)Marshal.ReadInt16(p, IntPtr.Size * 2);
                    ushort dlen = (ushort)Marshal.ReadInt16(p, IntPtr.Size * 2 + 2);
                    uint flags = (uint)Marshal.ReadInt32(p, IntPtr.Size * 2 + 4);
                    uint ttl = (uint)Marshal.ReadInt32(p, IntPtr.Size * 2 + 8);
                    IntPtr data = p + dataOff;
                    DnsRecord r;
                    switch (rtype)
                    {
                        case 1: { DnsRecord_A a = new DnsRecord_A(); a.IP4Address = new IPAddress((uint)Marshal.ReadInt32(data)).ToString(); r = a; break; }
                        case 28:
                        {
                            byte[] b = new byte[16]; Marshal.Copy(data, b, 0, 16);
                            DnsRecord_AAAA a = new DnsRecord_AAAA(); a.IP6Address = new IPAddress(b).ToString(); r = a; break;
                        }
                        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 39:
                            { DnsRecord_PTR a = new DnsRecord_PTR(); a.NameHost = Str(Marshal.ReadIntPtr(data)); r = a; break; }
                        case 15:
                        {
                            DnsRecord_MX a = new DnsRecord_MX(); a.NameExchange = Str(Marshal.ReadIntPtr(data));
                            a.Preference = (ushort)Marshal.ReadInt16(data, IntPtr.Size); r = a; break;
                        }
                        case 6:
                        {
                            DnsRecord_SOA a = new DnsRecord_SOA();
                            a.PrimaryServer = Str(Marshal.ReadIntPtr(data)); a.NameAdministrator = Str(Marshal.ReadIntPtr(data, IntPtr.Size));
                            int o = IntPtr.Size * 2;
                            a.SerialNumber = (uint)Marshal.ReadInt32(data, o); a.TimeToZoneRefresh = (uint)Marshal.ReadInt32(data, o + 4);
                            a.TimeToZoneFailureRetry = (uint)Marshal.ReadInt32(data, o + 8); a.TimeToExpiration = (uint)Marshal.ReadInt32(data, o + 12);
                            a.DefaultTTL = (uint)Marshal.ReadInt32(data, o + 16); r = a; break;
                        }
                        case 16:
                        {
                            DnsRecord_TXT a = new DnsRecord_TXT();
                            int cnt = Marshal.ReadInt32(data); List<string> l = new List<string>();
                            int arr = IntPtr.Size == 8 ? 8 : 4;
                            for (int i = 0; i < cnt; i++) l.Add(Str(Marshal.ReadIntPtr(data, arr + i * IntPtr.Size)));
                            a.Strings = l.ToArray(); r = a; break;
                        }
                        case 33:
                        {
                            DnsRecord_SRV a = new DnsRecord_SRV(); a.NameTarget = Str(Marshal.ReadIntPtr(data));
                            a.Priority = (ushort)Marshal.ReadInt16(data, IntPtr.Size); a.Weight = (ushort)Marshal.ReadInt16(data, IntPtr.Size + 2);
                            a.Port = (ushort)Marshal.ReadInt16(data, IntPtr.Size + 4); r = a; break;
                        }
                        default:
                        {
                            DnsRecord_Unknown a = new DnsRecord_Unknown(); byte[] b = new byte[dlen];
                            if (dlen > 0) Marshal.Copy(data, b, 0, dlen); a.Data = b; r = a; break;
                        }
                    }
                    r.Name = Str(pName); r.Type = (RecordType)rtype; r.Section = (DNSSection)(int)(flags & 3);
                    r.CharacterSet = (DNSCharset)(int)((flags >> 3) & 3); r.DataLength = dlen; r.TTL = ttl;
                    res.Add(r);
                    p = next;
                }
            }
            finally
            {
                if (list != IntPtr.Zero) DnsRecordListFree(list, 1);
                if (srv != IntPtr.Zero) Marshal.FreeHGlobal(srv);
            }
            return result;
        }

        public static ErrorRecord StampedError(Exception e, string errorId, ErrorCategory cat, object target, IScriptExtent position)
        {
            ErrorRecord rec = new ErrorRecord(e, errorId, cat, target);
            try
            {
                CmdletInfo info = new CmdletInfo("Resolve-DnsName", typeof(ResolveDnsName));
                InvocationInfo inv = InvocationInfo.Create(info, position);
                BindingFlags f = BindingFlags.NonPublic | BindingFlags.Instance;
                typeof(ErrorRecord).GetMethod("SetInvocationInfo", f).Invoke(rec, new object[] { inv });
                typeof(ErrorRecord).GetProperty("PreserveInvocationInfoOnce", f).SetValue(rec, true, null);
            }
            catch (Exception) { }
            return rec;
        }

        public static string ReverseName(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            StringBuilder sb = new StringBuilder();
            if (b.Length == 4) { for (int i = 3; i >= 0; i--) sb.Append(b[i]).Append('.'); sb.Append("in-addr.arpa"); }
            else { for (int i = 15; i >= 0; i--) sb.Append((b[i] & 0xF).ToString("x")).Append('.').Append((b[i] >> 4).ToString("x")).Append('.'); sb.Append("ip6.arpa"); }
            return sb.ToString();
        }
    }
}
