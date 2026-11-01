// Clean-room helper for the NetAdapter, NetTCPIP and DnsClient script modules of ReactOS-Nitro.
// Object model (CIM class names, property names and order, enum names and values) follows the public surface of the
// Windows modules as measured on Windows 10; the implementation is original and talks to iphlpapi, dnsapi and the
// registry only. NitroNetSpec.g.cs (generated) holds the enums and the object schemas.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace Nitro.Net
{
    // ------------------------------------------------------------------------------------------------ object builder
    // Builds PSObjects shaped like the CimInstance objects of the Windows cmdlets: the same type name chain, and the
    // members (computed ones, aliases, then the CIM properties) in the order Windows reports them.
    // The CLR object behind the CIM-shaped PSObjects. A PSCustomObject base would make Select-Object (-First 1 included)
    // copy the object into a "Selected." PSCustomObject; a CimInstance-like base is passed through, as on Windows.
    public sealed class CimLikeObject { public override string ToString() { return "CimInstance"; } }

    public static class CimBuilder
    {
        sealed class Member { public string Name, Kind, Cim, Aux; public Type Enum; }
        sealed class ClassInfo { public string Name; public string[] TypeNames; public Member[] Members; }
        static Dictionary<string, ClassInfo> classes;
        static readonly object gate = new object();

        static Dictionary<string, ClassInfo> Classes()
        {
            if (classes != null) return classes;
            lock (gate)
            {
                if (classes != null) return classes;
                Dictionary<string, ClassInfo> d = new Dictionary<string, ClassInfo>();
                Assembly asm = typeof(CimBuilder).Assembly;
                foreach (string[] s in Nitro.NetSchema.Schemas.All)
                {
                    ClassInfo ci = new ClassInfo();
                    ci.Name = s[0];
                    ci.TypeNames = s[1].Split('|');
                    List<Member> ms = new List<Member>();
                    foreach (string m in s[2].Split(';'))
                    {
                        string[] f = m.Split('~');
                        Member mem = new Member();
                        mem.Name = f[0]; mem.Kind = f[1]; mem.Cim = f[2]; mem.Aux = f[3];
                        if (mem.Kind == "S" && mem.Aux.Length > 0) mem.Enum = asm.GetType(mem.Aux);
                        ms.Add(mem);
                    }
                    ci.Members = ms.ToArray();
                    d[ci.Name] = ci;
                }
                classes = d;
                return d;
            }
        }

        static object Coerce(object v, string cim)
        {
            if (v == null) return null;
            PSObject po = v as PSObject;
            if (po != null) v = po.BaseObject;
            try
            {
                switch (cim)
                {
                    case "Boolean": return v is bool ? v : (object)Convert.ToBoolean(v, CultureInfo.InvariantCulture);
                    case "String": return v as string ?? Convert.ToString(v, CultureInfo.InvariantCulture);
                    case "UInt8": return v is byte ? v : (object)Convert.ToByte(v, CultureInfo.InvariantCulture);
                    case "UInt16": return v is ushort ? v : (object)Convert.ToUInt16(v, CultureInfo.InvariantCulture);
                    case "UInt32": return v is uint ? v : (object)Convert.ToUInt32(v, CultureInfo.InvariantCulture);
                    case "UInt64": return v is ulong ? v : (object)Convert.ToUInt64(v, CultureInfo.InvariantCulture);
                    case "UInt16Array": return v is ushort[] ? v : ToArray<ushort>(v);
                    case "UInt32Array": return v is uint[] ? v : ToArray<uint>(v);
                    case "StringArray": return v is string[] ? v : ToArray<string>(v);
                    default: return v;
                }
            }
            catch (Exception) { return v; }
        }

        static T[] ToArray<T>(object v)
        {
            List<T> l = new List<T>();
            IEnumerable e = v as IEnumerable;
            if (e == null || v is string) { l.Add((T)Convert.ChangeType(v, typeof(T), CultureInfo.InvariantCulture)); }
            else foreach (object o in e) l.Add((T)Convert.ChangeType(o, typeof(T), CultureInfo.InvariantCulture));
            return l.ToArray();
        }

        public static PSObject Create(string cls, IDictionary values)
        {
            ClassInfo ci = Classes()[cls];
            PSObject o = new PSObject(new CimLikeObject());
            o.TypeNames.Clear();
            foreach (string t in ci.TypeNames) o.TypeNames.Add(t);   // the measured chain already ends in CimInstance and System.Object
            foreach (Member m in ci.Members)
            {
                if (m.Kind == "A") { o.Members.Add(new PSAliasProperty(m.Name, m.Aux)); continue; }
                object v = values.Contains(m.Name) ? values[m.Name] : null;
                if (m.Kind == "S" && m.Enum != null && v != null)
                {
                    PSObject po = v as PSObject;
                    if (po != null) v = po.BaseObject;
                    if (v is string) v = Enum.Parse(m.Enum, (string)v);
                    else if (v.GetType() != m.Enum) v = Enum.ToObject(m.Enum, Convert.ToUInt64(v, CultureInfo.InvariantCulture));
                }
                else if (m.Kind == "P") v = Coerce(v, m.Cim);
                o.Members.Add(new PSNoteProperty(m.Name, v));
            }
            o.Members.Add(new PSNoteProperty("PSComputerName", null));
            return o;
        }
    }

    // ------------------------------------------------------------------------------------------------ native data
    public static class Native
    {
        const int AF_INET = 2, AF_INET6 = 23;

        [StructLayout(LayoutKind.Sequential)]
        struct AdapterAddresses
        {
            public uint Length, IfIndex;
            public IntPtr Next, AdapterName, FirstUnicast, FirstAnycast, FirstMulticast, FirstDns, DnsSuffix, Description, FriendlyName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Phys;
            public uint PhysLen, Flags, Mtu, IfType, OperStatus, Ipv6IfIndex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public uint[] Zones;
            public IntPtr FirstPrefix;
            public ulong TxSpeed, RxSpeed;
            public IntPtr FirstWins, FirstGateway;
            public uint Ipv4Metric, Ipv6Metric;
            public ulong Luid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UnicastAddress
        {
            public uint Length, Flags;
            public IntPtr Next, Sockaddr;
            public int SockaddrLen, PrefixOrigin, SuffixOrigin, DadState;
            public uint ValidLifetime, PreferredLifetime, LeaseLifetime;
            public byte OnLinkPrefixLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SockAddrNode { public uint Length, Reserved; public IntPtr Next, Sockaddr; public int SockaddrLen; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct IfRow2
        {
            public ulong Luid; public uint Index; public Guid InterfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string Alias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string Description;
            public uint PhysLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Phys;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Perm;
            public uint Mtu, Type, TunnelType, MediaType, PhysMedium, AccessType, DirectionType;
            public byte Flags;
            public uint OperStatus, AdminStatus, MediaConnectState;
            public Guid NetworkGuid; public uint ConnectionType;
            public ulong TxSpeed, RxSpeed, InOctets, InUcastPkts, InNUcastPkts, InDiscards, InErrors, InUnknownProtos,
                InUcastOctets, InMulticastOctets, InBroadcastOctets, OutOctets, OutUcastPkts, OutNUcastPkts, OutDiscards,
                OutErrors, OutUcastOctets, OutMulticastOctets, OutBroadcastOctets, OutQLen;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IpInterfaceRow
        {
            public ushort Family; public ulong Luid; public uint Index, MaxReassemblySize; public ulong InterfaceIdentifier;
            public uint MinRaInterval, MaxRaInterval;
            public byte Advertising, Forwarding, WeakHostSend, WeakHostReceive, AutoMetric, NeighborUnreachability, ManagedAddress, OtherStateful, AdvertiseDefaultRoute;
            public int RouterDiscovery;
            public uint DadTransmits, BaseReachableTime, RetransmitTime, PathMtuDiscoveryTimeout;
            public int LinkLocalBehavior; public uint LinkLocalTimeout;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public uint[] Zones;
            public uint SitePrefixLength, Metric, NlMtu;
            public byte Connected, WakeUp, SupportsND, SupportsRD;
            public uint ReachableTime;
            public byte TxOffload, RxOffload, DisableDefaultRoutes;
        }

        [DllImport("iphlpapi.dll")] static extern uint GetAdaptersAddresses(uint family, uint flags, IntPtr reserved, IntPtr buf, ref uint size);
        [DllImport("iphlpapi.dll")] static extern uint GetIfTable2(out IntPtr table);
        [DllImport("iphlpapi.dll")] static extern uint GetIpInterfaceTable(ushort family, out IntPtr table);
        [DllImport("iphlpapi.dll")] static extern uint GetUnicastIpAddressTable(ushort family, out IntPtr table);
        [DllImport("iphlpapi.dll")] static extern void FreeMibTable(IntPtr table);
        [DllImport("iphlpapi.dll")] static extern uint GetIpForwardTable(IntPtr table, ref uint size, bool order);
        [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table, ref uint size, bool order, uint family, int cls, uint reserved);
        [DllImport("iphlpapi.dll")] static extern uint GetExtendedUdpTable(IntPtr table, ref uint size, bool order, uint family, int cls, uint reserved);

        public static string MachineName { get { return Environment.MachineName; } }

        // ---- helpers
        static string SockaddrToString(IntPtr sa)
        {
            if (sa == IntPtr.Zero) return null;
            int fam = Marshal.ReadInt16(sa);
            if (fam == AF_INET)
            {
                byte[] b = new byte[4]; Marshal.Copy(sa + 4, b, 0, 4);
                return new IPAddress(b).ToString();
            }
            if (fam == AF_INET6)
            {
                byte[] b = new byte[16]; Marshal.Copy(sa + 8, b, 0, 16);
                long scope = (uint)Marshal.ReadInt32(sa + 24);
                return new IPAddress(b, scope).ToString();
            }
            return null;
        }

        static string Ipv4(uint addr) { return new IPAddress(addr).ToString(); }
        static string Ipv6(IntPtr p, long scope) { byte[] b = new byte[16]; Marshal.Copy(p, b, 0, 16); return new IPAddress(b, scope).ToString(); }
        static ushort Port(int raw) { return (ushort)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)); }
        static TimeSpan Lifetime(uint secs) { return secs == 0xFFFFFFFF ? TimeSpan.MaxValue : TimeSpan.FromSeconds(secs); }
        static ulong Speed(ulong v) { return v == ulong.MaxValue ? 0 : v; }

        public static string MacString(byte[] mac, int len, string sep)
        {
            if (mac == null || len <= 0) return "";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len && i < mac.Length; i++) { if (i > 0 && sep.Length > 0) sb.Append(sep); sb.Append(mac[i].ToString("X2")); }
            return sb.ToString();
        }

        static string IfTypeName(uint ifType)
        {
            switch (ifType)
            {
                case 6: case 62: case 69: case 117: return "ethernet";
                case 71: return "wireless";
                case 24: return "loopback";
                case 131: return "tunnel";
                case 23: return "ppp";
                default: return "other";
            }
        }

        public static string FormatLinkSpeed(ulong bps)
        {
            double v; string unit;
            if (bps >= 1000000000UL) { v = bps / 1e9; unit = "Gbps"; }
            else if (bps >= 1000000UL) { v = bps / 1e6; unit = "Mbps"; }
            else if (bps >= 1000UL) { v = bps / 1e3; unit = "Kbps"; }
            else { v = bps; unit = "bps"; }
            return v.ToString("0.##", CultureInfo.InvariantCulture) + " " + unit;
        }

        static string MediaTypeName(uint m)
        {
            switch (m)
            {
                case 0: return "802.3"; case 3: return "WAN"; case 9: return "Wireless WAN"; case 12: return "Connection Oriented WAN";
                case 15: return "Tunnel"; case 16: return "Native 802.11"; case 17: return "Loopback"; case 18: return "WiMAX"; case 19: return "IP";
                default: return "Unknown";
            }
        }

        static string PhysicalMediaName(uint m)
        {
            switch (m)
            {
                case 0: return "Unspecified"; case 1: return "Wireless LAN"; case 2: return "Cable Modem"; case 8: return "Wireless WAN";
                case 9: return "Native 802.11"; case 10: return "BlueTooth"; case 11: return "Infiniband"; case 12: return "WiMAX"; case 13: return "UWB";
                case 14: return "802.3"; case 16: return "IRDA"; case 17: return "Wired WAN"; case 18: return "Wired Connection Oriented WAN"; case 19: return "Other";
                default: return "Unknown";
            }
        }

        static string StatusName(uint oper, uint admin, bool mediaDisconnected)
        {
            switch (oper)
            {
                case 1: return "Up";
                case 3: return "Testing";
                case 4: return "Unknown";
                case 5: return "Dormant";
                case 6: return "Not Present";
                case 7: return "Lower Layer Down";
                case 2:
                    if (admin == 2) return "Disabled";
                    return mediaDisconnected ? "Disconnected" : "Disconnected";
                default: return null;
            }
        }

        // ---- registry: driver details of a network adapter
        sealed class DriverInfo { public string Desc, Provider, Version, Date, Component, Service, ImagePath, PnpId; }

        static DriverInfo ReadDriver(string guid)
        {
            DriverInfo di = new DriverInfo();
            try
            {
                using (RegistryKey cls = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"))
                {
                    if (cls != null)
                        foreach (string sub in cls.GetSubKeyNames())
                        {
                            using (RegistryKey k = cls.OpenSubKey(sub))
                            {
                                if (k == null) continue;
                                string id = k.GetValue("NetCfgInstanceId") as string;
                                if (id == null || !id.Equals(guid, StringComparison.OrdinalIgnoreCase)) continue;
                                di.Desc = k.GetValue("DriverDesc") as string;
                                di.Provider = k.GetValue("ProviderName") as string;
                                di.Version = k.GetValue("DriverVersion") as string;
                                di.Date = k.GetValue("DriverDate") as string;
                                di.Component = k.GetValue("MatchingDeviceId") as string;
                                break;
                            }
                        }
                }
                using (RegistryKey conn = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\" + guid + @"\Connection"))
                    if (conn != null) di.PnpId = conn.GetValue("PnpInstanceID") as string;
                if (di.PnpId != null)
                    using (RegistryKey en = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + di.PnpId))
                        if (en != null) di.Service = en.GetValue("Service") as string;
                if (di.Service != null)
                    using (RegistryKey sv = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + di.Service))
                        if (sv != null) di.ImagePath = sv.GetValue("ImagePath") as string;
            }
            catch (Exception) { }
            return di;
        }

        // ---- adapters and interface tables
        // an address as read: the family and text are taken while the system buffer is alive
        sealed class Uni { public UnicastAddress U; public string Text; public int Family; }

        sealed class Aa
        {
            public AdapterAddresses H;
            public string Description, Friendly, Guid;
            public List<Uni> Unicast = new List<Uni>();
            public List<string> Dns = new List<string>();
            public List<string> Dns6 = new List<string>();
            public List<string> Gateways = new List<string>();
        }

        static List<Aa> ReadAdapters()
        {
            List<Aa> list = new List<Aa>();
            uint size = 32768;
            IntPtr buf = IntPtr.Zero;
            try
            {
                uint rc = 111;
                for (int i = 0; i < 6 && rc == 111; i++)
                {
                    if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                    buf = Marshal.AllocHGlobal((int)size);
                    rc = GetAdaptersAddresses(0, 0x10 | 0x80 | 0x100, IntPtr.Zero, buf, ref size);
                }
                if (rc != 0) return list;
                int need = (int)Marshal.OffsetOf(typeof(AdapterAddresses), "Luid") + 8;
                for (IntPtr p = buf; p != IntPtr.Zero; )
                {
                    AdapterAddresses h = (AdapterAddresses)Marshal.PtrToStructure(p, typeof(AdapterAddresses));
                    Aa a = new Aa();
                    a.H = h;
                    if (h.Length < need) { a.H.Luid = 0; a.H.Ipv4Metric = 0; a.H.Ipv6Metric = 0; a.H.FirstGateway = IntPtr.Zero; a.H.TxSpeed = 0; a.H.RxSpeed = 0; }
                    a.Guid = h.AdapterName != IntPtr.Zero ? Marshal.PtrToStringAnsi(h.AdapterName) : null;
                    a.Description = h.Description != IntPtr.Zero ? Marshal.PtrToStringUni(h.Description) : null;
                    a.Friendly = h.FriendlyName != IntPtr.Zero ? Marshal.PtrToStringUni(h.FriendlyName) : null;
                    for (IntPtr u = h.FirstUnicast; u != IntPtr.Zero; )
                    {
                        UnicastAddress ua = (UnicastAddress)Marshal.PtrToStructure(u, typeof(UnicastAddress));
                        Uni x = new Uni(); x.U = ua; x.Text = SockaddrToString(ua.Sockaddr);
                        x.Family = ua.Sockaddr != IntPtr.Zero ? Marshal.ReadInt16(ua.Sockaddr) : 0;
                        a.Unicast.Add(x);
                        u = ua.Next;
                    }
                    for (IntPtr d = h.FirstDns; d != IntPtr.Zero; )
                    {
                        SockAddrNode n = (SockAddrNode)Marshal.PtrToStructure(d, typeof(SockAddrNode));
                        string s = SockaddrToString(n.Sockaddr);
                        if (s != null) { if (Marshal.ReadInt16(n.Sockaddr) == AF_INET6) a.Dns6.Add(s); else a.Dns.Add(s); }
                        d = n.Next;
                    }
                    if (a.H.FirstGateway != IntPtr.Zero)
                        for (IntPtr g = a.H.FirstGateway; g != IntPtr.Zero; )
                        {
                            SockAddrNode n = (SockAddrNode)Marshal.PtrToStructure(g, typeof(SockAddrNode));
                            string s = SockaddrToString(n.Sockaddr);
                            if (s != null) a.Gateways.Add(s);
                            g = n.Next;
                        }
                    list.Add(a);
                    p = h.Next;
                }
            }
            catch (Exception) { }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
            return list;
        }

        static Dictionary<uint, IfRow2> ReadIfRows()
        {
            Dictionary<uint, IfRow2> d = new Dictionary<uint, IfRow2>();
            IntPtr t = IntPtr.Zero;
            try
            {
                if (GetIfTable2(out t) != 0 || t == IntPtr.Zero) return d;
                uint n = (uint)Marshal.ReadInt32(t);
                int stride = Marshal.SizeOf(typeof(IfRow2));
                for (uint i = 0; i < n; i++)
                {
                    IfRow2 r = (IfRow2)Marshal.PtrToStructure(t + 8 + (int)(i * stride), typeof(IfRow2));
                    d[r.Index] = r;
                }
            }
            catch (Exception) { }
            finally { if (t != IntPtr.Zero) FreeMibTable(t); }
            return d;
        }

        static List<IpInterfaceRow> ReadIpInterfaces()
        {
            List<IpInterfaceRow> l = new List<IpInterfaceRow>();
            IntPtr t = IntPtr.Zero;
            try
            {
                if (GetIpInterfaceTable(0, out t) != 0 || t == IntPtr.Zero) return l;
                uint n = (uint)Marshal.ReadInt32(t);
                int stride = Marshal.SizeOf(typeof(IpInterfaceRow));
                for (uint i = 0; i < n; i++)
                    l.Add((IpInterfaceRow)Marshal.PtrToStructure(t + 8 + (int)(i * stride), typeof(IpInterfaceRow)));
            }
            catch (Exception) { }
            finally { if (t != IntPtr.Zero) FreeMibTable(t); }
            return l;
        }

        static bool IsVisibleType(uint t)
        {
            return t == 6 || t == 62 || t == 69 || t == 117 || t == 71 || t == 53 || t == 135 || t == 144;
        }

        static uint IndexOf(Aa a) { return a.H.IfIndex != 0 ? a.H.IfIndex : a.H.Ipv6IfIndex; }

        // ---- NetAdapter
        public static List<Dictionary<string, object>> Adapters()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            Dictionary<uint, IfRow2> rows = ReadIfRows();
            foreach (Aa a in ReadAdapters())
            {
                uint idx = IndexOf(a);
                IfRow2 r; bool haveRow = rows.TryGetValue(idx, out r);
                Dictionary<string, object> d = new Dictionary<string, object>();
                string guid = a.Guid ?? "";
                if (guid.Length > 0 && guid[0] != '{') guid = "{" + guid + "}";
                guid = guid.ToUpperInvariant();
                uint ifType = haveRow ? r.Type : a.H.IfType;
                ulong luid = haveRow && r.Luid != 0 ? r.Luid : a.H.Luid;
                uint oper = haveRow ? r.OperStatus : a.H.OperStatus;
                uint admin = haveRow && r.AdminStatus != 0 ? r.AdminStatus : 1;
                uint media = haveRow && r.MediaConnectState != 0 ? r.MediaConnectState : (oper == 1 ? 1u : 2u);
                ulong tx = Speed(haveRow && r.TxSpeed != 0 ? r.TxSpeed : a.H.TxSpeed);
                ulong rx = Speed(haveRow && r.RxSpeed != 0 ? r.RxSpeed : a.H.RxSpeed);
                uint mtu = haveRow && r.Mtu != 0 ? r.Mtu : a.H.Mtu;
                uint ndisMedium = haveRow ? r.MediaType : (ifType == 24 ? 17u : ifType == 131 ? 15u : ifType == 71 ? 16u : 0u);
                uint physMedium = haveRow ? r.PhysMedium : 0;
                byte[] mac = a.H.Phys; int macLen = (int)a.H.PhysLen;
                if (macLen == 0 && haveRow && r.PhysLen > 0) { mac = r.Phys; macLen = (int)r.PhysLen; }
                bool hidden = !IsVisibleType(ifType);
                bool hw = haveRow && r.Flags != 0 ? (r.Flags & 1) != 0 : (ifType == 6 || ifType == 71);
                bool connectorPresent = haveRow && r.Flags != 0 ? (r.Flags & 4) != 0 : oper != 6;
                bool endpoint = haveRow && (r.Flags & 0x80) != 0;
                bool mediaDisc = media == 2;
                DriverInfo di = ReadDriver(guid);

                d["Name"] = a.Friendly ?? (haveRow ? r.Alias : null);
                d["InterfaceDescription"] = a.Description ?? (haveRow ? r.Description : null);
                d["InstanceID"] = guid; d["DeviceID"] = guid; d["InterfaceGuid"] = guid;
                d["CreationClassName"] = "MSFT_NetAdapter"; d["SystemCreationClassName"] = "CIM_NetworkPort"; d["SystemName"] = MachineName;
                d["EnabledDefault"] = 2; d["EnabledState"] = 5; d["RequestedState"] = 12; d["TransitioningToState"] = 12;
                d["Speed"] = tx; d["ActiveMaximumTransmissionUnit"] = (ulong)mtu; d["PortNumber"] = 0;
                string macPlain = MacString(mac, macLen, "");
                d["NetworkAddresses"] = macLen > 0 ? new string[] { macPlain } : null;
                d["PermanentAddress"] = macLen > 0 ? macPlain : null;
                d["AdminLocked"] = false; d["ConnectorPresent"] = connectorPresent;
                d["DeviceName"] = @"\Device\" + guid; d["DeviceWakeUpEnable"] = false;
                d["DriverDescription"] = di.Desc ?? a.Description;
                d["DriverProvider"] = di.Provider;
                d["DriverVersionString"] = di.Version;
                string dateText = null; ulong dateData = 0; bool haveDate = false;
                DateTime dt;
                if (di.Date != null && DateTime.TryParse(di.Date, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out dt))
                { dateText = dt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture); dateData = (ulong)dt.ToFileTimeUtc(); haveDate = true; }
                d["DriverDate"] = dateText; d["DriverDateData"] = haveDate ? (object)dateData : null;
                if (di.Version != null)
                {
                    string[] vp = di.Version.Split('.');
                    ushort maj, min;
                    if (vp.Length >= 4 && ushort.TryParse(vp[2], out maj) && ushort.TryParse(vp[3], out min)) { d["MajorDriverVersion"] = maj; d["MinorDriverVersion"] = (ushort)(min & 0xFF); }
                }
                string driverName = null;
                if (di.ImagePath != null)
                {
                    string leaf = di.ImagePath; int k = leaf.LastIndexOf('\\'); if (k >= 0) leaf = leaf.Substring(k + 1);
                    driverName = @"\SystemRoot\System32\drivers\" + leaf;
                }
                d["DriverName"] = driverName;
                d["ComponentID"] = di.Component;
                d["PnPDeviceID"] = di.PnpId;
                d["EndPointInterface"] = endpoint; d["HardwareInterface"] = hw; d["Hidden"] = hidden; d["IMFilter"] = false;
                d["InterfaceAdminStatus"] = admin; d["InterfaceIndex"] = idx;
                d["InterfaceName"] = IfTypeName(ifType) + "_" + ((luid >> 24) & 0xFFFFFF).ToString(CultureInfo.InvariantCulture);
                d["InterfaceOperationalStatus"] = oper; d["InterfaceType"] = ifType; d["iSCSIInterface"] = false;
                d["MediaConnectState"] = media; d["MediaDuplexState"] = 0u; d["MtuSize"] = mtu;
                d["NdisMedium"] = ndisMedium; d["NdisPhysicalMedium"] = physMedium;
                d["NetLuid"] = luid; d["NetLuidIndex"] = (uint)((luid >> 24) & 0xFFFFFF);
                d["NotUserRemovable"] = false; d["OperationalStatusDownDefaultPortNotAuthenticated"] = false;
                d["OperationalStatusDownInterfacePaused"] = false; d["OperationalStatusDownLowPowerState"] = false;
                d["OperationalStatusDownMediaDisconnected"] = oper == 2 && mediaDisc;
                d["PromiscuousMode"] = false; d["ReceiveLinkSpeed"] = rx; d["TransmitLinkSpeed"] = tx;
                d["Virtual"] = !hw && !hidden; d["VlanID"] = (ushort)0; d["WdmInterface"] = false;
                // computed members
                d["MacAddress"] = MacString(mac, macLen, "-");
                d["Status"] = StatusName(oper, admin, mediaDisc);
                d["LinkSpeed"] = FormatLinkSpeed(tx);
                d["MediaType"] = MediaTypeName(ndisMedium);
                d["PhysicalMediaType"] = PhysicalMediaName(physMedium);
                d["AdminStatus"] = admin; d["MediaConnectionState"] = media; d["ifOperStatus"] = oper;
                d["DriverFileName"] = driverName != null ? driverName.Substring(driverName.LastIndexOf('\\') + 1) : null;
                d["NdisVersion"] = "Unknown";
                string info = "Driver Date " + dateText + " Version " + di.Version;
                d["DriverInformation"] = info;
                d["_ifIndex"] = idx; d["_ifType"] = ifType;
                res.Add(d);
            }
            return res;
        }

        // ---- NetAdapterStatistics
        public static List<Dictionary<string, object>> AdapterStats()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            Dictionary<uint, IfRow2> rows = ReadIfRows();
            foreach (Dictionary<string, object> ad in Adapters())
            {
                IfRow2 r; if (!rows.TryGetValue((uint)ad["_ifIndex"], out r)) continue;
                Dictionary<string, object> d = new Dictionary<string, object>();
                string desc = (string)ad["InterfaceDescription"];
                d["Caption"] = "MSFT_NetAdapterStatisticsSettingData '" + desc + "'";
                d["Description"] = desc; d["ElementName"] = desc; d["InstanceID"] = ad["InstanceID"];
                d["InterfaceDescription"] = desc; d["Name"] = ad["Name"]; d["Source"] = 2u; d["SystemName"] = MachineName;
                d["OutboundDiscardedPackets"] = r.OutDiscards; d["OutboundPacketErrors"] = r.OutErrors;
                d["ReceivedBroadcastBytes"] = r.InBroadcastOctets; d["ReceivedBroadcastPackets"] = null;
                d["ReceivedBytes"] = r.InOctets; d["ReceivedDiscardedPackets"] = r.InDiscards;
                d["ReceivedMulticastBytes"] = r.InMulticastOctets; d["ReceivedMulticastPackets"] = null;
                d["ReceivedPacketErrors"] = r.InErrors; d["ReceivedUnicastBytes"] = r.InUcastOctets; d["ReceivedUnicastPackets"] = r.InUcastPkts;
                d["SentBroadcastBytes"] = r.OutBroadcastOctets; d["SentBroadcastPackets"] = null;
                d["SentBytes"] = r.OutOctets; d["SentMulticastBytes"] = r.OutMulticastOctets; d["SentMulticastPackets"] = null;
                d["SentUnicastBytes"] = r.OutUcastOctets; d["SentUnicastPackets"] = r.OutUcastPkts;
                res.Add(d);
            }
            return res;
        }

        // ---- NetIPAddress (GetUnicastIpAddressTable: MIB_UNICASTIPADDRESS_ROW, 80 bytes, rows from offset 8)
        sealed class UniRow { public int Family; public string Text; public uint Index; public uint PrefixOrigin, SuffixOrigin, Valid, Preferred, DadState; public byte PrefixLength; public bool SkipAsSource; }

        static List<UniRow> ReadUnicast()
        {
            List<UniRow> l = new List<UniRow>();
            IntPtr t = IntPtr.Zero;
            try
            {
                if (GetUnicastIpAddressTable(0, out t) != 0 || t == IntPtr.Zero) return null;
                uint n = (uint)Marshal.ReadInt32(t);
                for (uint i = 0; i < n; i++)
                {
                    IntPtr row = t + 8 + (int)(i * 80);
                    UniRow u = new UniRow();
                    u.Family = Marshal.ReadInt16(row);
                    u.Text = SockaddrToString(row);
                    u.Index = (uint)Marshal.ReadInt32(row, 40);
                    u.PrefixOrigin = (uint)Marshal.ReadInt32(row, 44); u.SuffixOrigin = (uint)Marshal.ReadInt32(row, 48);
                    u.Valid = (uint)Marshal.ReadInt32(row, 52); u.Preferred = (uint)Marshal.ReadInt32(row, 56);
                    u.PrefixLength = Marshal.ReadByte(row, 60); u.SkipAsSource = Marshal.ReadByte(row, 61) != 0;
                    u.DadState = (uint)Marshal.ReadInt32(row, 64);
                    if (u.Text != null) l.Add(u);
                }
            }
            catch (Exception) { return null; }
            finally { if (t != IntPtr.Zero) FreeMibTable(t); }
            return l;
        }

        public static List<Dictionary<string, object>> IPAddresses()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            List<Aa> ads = ReadAdapters();
            List<UniRow> rows = ReadUnicast();
            if (rows == null)
            {
                // fall back to the adapter list: what it does not carry (origins, DAD state) is reported as unknown
                rows = new List<UniRow>();
                foreach (Aa a in ads)
                    foreach (Uni x in a.Unicast)
                    {
                        if (x.Text == null) continue;
                        UniRow u = new UniRow();
                        u.Family = x.Family; u.Text = x.Text; u.Index = IndexOf(a);
                        u.PrefixOrigin = (uint)x.U.PrefixOrigin; u.SuffixOrigin = (uint)x.U.SuffixOrigin; u.Valid = x.U.ValidLifetime; u.Preferred = x.U.PreferredLifetime;
                        u.PrefixLength = x.U.OnLinkPrefixLength; u.DadState = (uint)x.U.DadState;
                        rows.Add(u);
                    }
            }
            foreach (UniRow u in rows)
            {
                Aa a = null; foreach (Aa x in ads) if (IndexOf(x) == u.Index || x.H.IfIndex == u.Index || x.H.Ipv6IfIndex == u.Index) { a = x; break; }
                bool v6 = u.Family == AF_INET6;
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["InstanceID"] = u.Text + "++" + u.Index; d["Name"] = (a != null ? a.Guid : "") + ":" + u.Text;
                d["CreationClassName"] = ""; d["SystemCreationClassName"] = ""; d["SystemName"] = "";
                d["EnabledDefault"] = 2; d["RequestedState"] = 12; d["TransitioningToState"] = 12;
                d["ProtocolIFType"] = 4096; d["AddressOrigin"] = 0;
                if (v6) d["IPv6Address"] = u.Text; else d["IPv4Address"] = u.Text;
                d["PrefixLength"] = u.PrefixLength;
                d["AddressFamily"] = v6 ? AF_INET6 : AF_INET;
                d["AddressState"] = u.DadState;
                d["InterfaceAlias"] = a != null ? a.Friendly : null; d["InterfaceIndex"] = u.Index; d["IPAddress"] = u.Text;
                d["PreferredLifetime"] = Lifetime(u.Preferred);
                d["PrefixOrigin"] = u.PrefixOrigin; d["SkipAsSource"] = u.SkipAsSource;
                d["Store"] = 1; d["SuffixOrigin"] = u.SuffixOrigin; d["Type"] = 1;
                d["ValidLifetime"] = Lifetime(u.Valid);
                res.Add(d);
            }
            return res;
        }

        // ---- NetIPInterface
        public static List<Dictionary<string, object>> IPInterfaces()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            List<Aa> ads = ReadAdapters();
            List<IpInterfaceRow> rows = ReadIpInterfaces();
            foreach (Aa a in ads)
            {
                uint idx = IndexOf(a);
                foreach (int fam in new int[] { AF_INET6, AF_INET })
                {
                    uint ix = fam == AF_INET ? a.H.IfIndex : a.H.Ipv6IfIndex;
                    IpInterfaceRow r = default(IpInterfaceRow); bool have = false;
                    foreach (IpInterfaceRow x in rows) if (x.Family == fam && (x.Index == ix || (ix != 0 && x.Luid != 0 && x.Luid == a.H.Luid))) { r = x; have = true; break; }
                    if (!have && ix == 0) continue;
                    bool hasAddr = false;
                    foreach (Uni u in a.Unicast) if (u.Family == fam) hasAddr = true;
                    if (!have && !hasAddr && fam == AF_INET6) continue;
                    Dictionary<string, object> d = new Dictionary<string, object>();
                    d["InstanceID"] = (a.Guid ?? "") + ":" + (fam == AF_INET ? "IPv4" : "IPv6");
                    d["Name"] = idx.ToString(CultureInfo.InvariantCulture); d["ElementName"] = a.Friendly;
                    d["EnabledDefault"] = 2; d["EnabledState"] = 5; d["RequestedState"] = 12; d["TransitioningToState"] = 12;
                    d["CreationClassName"] = ""; d["SystemCreationClassName"] = ""; d["SystemName"] = idx.ToString(CultureInfo.InvariantCulture);
                    d["AddressFamily"] = fam;
                    d["AdvertiseDefaultRoute"] = have ? r.AdvertiseDefaultRoute : 0;
                    d["AdvertisedRouterLifetime"] = TimeSpan.FromMinutes(30);
                    d["Advertising"] = have ? r.Advertising : 0;
                    d["AutomaticMetric"] = have ? r.AutoMetric : 1;
                    d["BaseReachableTime"] = have ? r.BaseReachableTime : 30000u;
                    d["ClampMss"] = 0;
                    d["CompartmentId"] = 1u;
                    d["ConnectionState"] = have ? r.Connected : (a.H.OperStatus == 1 ? 1 : 0);
                    d["CurrentHopLimit"] = 0u;
                    d["DadRetransmitTime"] = 1000u;
                    d["DadTransmits"] = have ? r.DadTransmits : 1u;
                    d["Dhcp"] = fam == AF_INET ? ((a.H.Flags & 4) != 0 ? 1 : 0) : ((a.H.Flags & 4) != 0 ? 1 : 0);
                    d["DirectedMacWolPattern"] = 0; d["EcnMarking"] = 3; d["ForceArpNdWolPattern"] = 0;
                    d["Forwarding"] = have ? r.Forwarding : 0;
                    d["IgnoreDefaultRoutes"] = have ? r.DisableDefaultRoutes : 0;
                    d["InterfaceAlias"] = a.Friendly; d["InterfaceIndex"] = idx;
                    d["InterfaceMetric"] = have ? r.Metric : (fam == AF_INET ? a.H.Ipv4Metric : a.H.Ipv6Metric);
                    d["IsolationId"] = 0u; d["LowestIfNetLuid"] = a.H.Luid;
                    d["ManagedAddressConfiguration"] = have ? r.ManagedAddress : 0;
                    d["NeighborDiscoverySupported"] = have ? r.SupportsND : (fam == AF_INET6 ? 1 : 0);
                    d["NeighborUnreachabilityDetection"] = have ? r.NeighborUnreachability : 1;
                    d["NlMtu"] = have && r.NlMtu != 0 ? r.NlMtu : a.H.Mtu;
                    d["OtherStatefulConfiguration"] = have ? r.OtherStateful : 0;
                    d["ReachableTime"] = have ? r.ReachableTime : 30000u;
                    d["RetransmitTime"] = have ? r.RetransmitTime : 1000u;
                    d["RouterDiscovery"] = have ? (r.RouterDiscovery < 0 || r.RouterDiscovery > 2 ? 0 : r.RouterDiscovery) : 1;
                    d["Store"] = 1;
                    d["WeakHostReceive"] = have ? r.WeakHostReceive : 0; d["WeakHostSend"] = have ? r.WeakHostSend : 0;
                    d["_ifIndex"] = idx;
                    res.Add(d);
                }
            }
            return res;
        }

        // ---- NetRoute (the IPv4 forwarding table: GetIpForwardTable2 is not available on this system)
        public static List<Dictionary<string, object>> Routes()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            List<Aa> ads = ReadAdapters();
            List<IpInterfaceRow> ifRows = ReadIpInterfaces();
            uint size = 4096; IntPtr buf = IntPtr.Zero;
            try
            {
                uint rc = 122;
                for (int i = 0; i < 6 && rc == 122; i++)
                {
                    if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                    buf = Marshal.AllocHGlobal((int)size);
                    rc = GetIpForwardTable(buf, ref size, false);
                }
                if (rc != 0) return res;
                uint n = (uint)Marshal.ReadInt32(buf);
                for (uint i = 0; i < n; i++)
                {
                    IntPtr row = buf + 4 + (int)(i * 56);
                    uint dest = (uint)Marshal.ReadInt32(row), mask = (uint)Marshal.ReadInt32(row, 4), next = (uint)Marshal.ReadInt32(row, 12);
                    uint idx = (uint)Marshal.ReadInt32(row, 16), type = (uint)Marshal.ReadInt32(row, 20), proto = (uint)Marshal.ReadInt32(row, 24);
                    uint metric = (uint)Marshal.ReadInt32(row, 36);
                    int plen = 0; uint m = (uint)IPAddress.NetworkToHostOrder((int)mask);
                    while (m != 0) { plen++; m <<= 1; }
                    Aa a = null; foreach (Aa x in ads) if (IndexOf(x) == idx || x.H.IfIndex == idx) { a = x; break; }
                    uint ifMetric = a != null ? a.H.Ipv4Metric : 0;
                    foreach (IpInterfaceRow ir in ifRows) if (ir.Family == AF_INET && ir.Index == idx) { ifMetric = ir.Metric; break; }
                    uint routeMetric = metric >= ifMetric ? metric - ifMetric : metric;
                    string prefix = Ipv4(dest) + "/" + plen.ToString(CultureInfo.InvariantCulture);
                    // the legacy table gives an on-link route the interface's own address as next hop; MSFT_NetRoute says 0.0.0.0
                    string nextText = Ipv4(next);
                    if (a != null) foreach (Uni own in a.Unicast) if (own.Text == nextText) { nextText = "0.0.0.0"; break; }
                    Dictionary<string, object> d = new Dictionary<string, object>();
                    d["InstanceID"] = prefix + "++" + nextText + "++" + idx.ToString(CultureInfo.InvariantCulture);
                    d["RouteMetric"] = routeMetric > 65535 ? 65535 : routeMetric; d["TypeOfRoute"] = type;
                    d["AddressFamily"] = AF_INET; d["CompartmentId"] = 1u; d["DestinationPrefix"] = prefix;
                    d["InterfaceAlias"] = a != null ? a.Friendly : null; d["InterfaceIndex"] = idx; d["InterfaceMetric"] = ifMetric;
                    d["NextHop"] = nextText;
                    d["PreferredLifetime"] = TimeSpan.MaxValue; d["ValidLifetime"] = TimeSpan.MaxValue;
                    d["Protocol"] = proto == 0 ? 1u : proto; d["Publish"] = 0; d["State"] = 0; d["Store"] = 1;
                    res.Add(d);
                }
            }
            catch (Exception) { }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
            return res;
        }

        // The route Windows would use for a destination: longest prefix, then lowest total metric. ifIndex 0 = any.
        public static Dictionary<string, object> FindRoute(IPAddress dest, uint ifIndex)
        {
            Dictionary<string, object> best = null; int bestLen = -1; long bestMetric = long.MaxValue;
            if (dest.AddressFamily != AddressFamily.InterNetwork) return null;
            uint dv = BitConverter.ToUInt32(dest.GetAddressBytes(), 0);
            foreach (Dictionary<string, object> r in Routes())
            {
                if (ifIndex != 0 && (uint)r["InterfaceIndex"] != ifIndex) continue;
                string[] p = ((string)r["DestinationPrefix"]).Split('/');
                int len = int.Parse(p[1], CultureInfo.InvariantCulture);
                uint pv = BitConverter.ToUInt32(IPAddress.Parse(p[0]).GetAddressBytes(), 0);
                uint mask = len == 0 ? 0u : (uint)IPAddress.HostToNetworkOrder((int)(0xFFFFFFFFu << (32 - len)));
                if ((dv & mask) != (pv & mask)) continue;
                long metric = Convert.ToInt64(r["RouteMetric"]) + Convert.ToInt64(r["InterfaceMetric"]);
                if (len > bestLen || (len == bestLen && metric < bestMetric)) { best = r; bestLen = len; bestMetric = metric; }
            }
            return best;
        }

        // ---- NetTCPConnection / NetUDPEndpoint
        static IntPtr ReadTable(bool tcp, uint family, int cls)
        {
            uint size = 16384; IntPtr buf = IntPtr.Zero; uint rc = 122;
            for (int i = 0; i < 8 && rc == 122; i++)
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal((int)size);
                rc = tcp ? GetExtendedTcpTable(buf, ref size, false, family, cls, 0) : GetExtendedUdpTable(buf, ref size, false, family, cls, 0);
            }
            if (rc != 0) { Marshal.FreeHGlobal(buf); return IntPtr.Zero; }
            return buf;
        }

        static DateTime? FileTimeToLocal(long ft)
        {
            if (ft <= 0) return null;
            try { return DateTime.FromFileTime(ft); } catch (Exception) { return null; }
        }

        public static List<Dictionary<string, object>> TcpConnections()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (uint fam in new uint[] { AF_INET6, AF_INET })
            {
                bool module = true;
                IntPtr buf = ReadTable(true, fam, 8);               // TCP_TABLE_OWNER_MODULE_ALL: has the creation time
                if (buf == IntPtr.Zero) { module = false; buf = ReadTable(true, fam, 5); }   // TCP_TABLE_OWNER_PID_ALL
                if (buf == IntPtr.Zero) continue;
                try
                {
                    uint n = (uint)Marshal.ReadInt32(buf);
                    int stride = fam == AF_INET ? (module ? 160 : 24) : (module ? 192 : 56);
                    int first = module ? 8 : 4;     // the module rows hold a 64-bit timestamp: the table starts on an 8-byte boundary
                    for (uint i = 0; i < n; i++)
                    {
                        IntPtr row = buf + first + (int)(i * stride);
                        string la, ra; ushort lp, rp; uint state, pid; long ts;
                        if (fam == AF_INET)
                        {
                            state = (uint)Marshal.ReadInt32(row); la = Ipv4((uint)Marshal.ReadInt32(row, 4)); lp = Port(Marshal.ReadInt32(row, 8));
                            ra = Ipv4((uint)Marshal.ReadInt32(row, 12)); rp = Port(Marshal.ReadInt32(row, 16)); pid = (uint)Marshal.ReadInt32(row, 20);
                            ts = module ? Marshal.ReadInt64(row, 24) : 0;
                        }
                        else
                        {
                            la = Ipv6(row, (uint)Marshal.ReadInt32(row, 16)); lp = Port(Marshal.ReadInt32(row, 20));
                            ra = Ipv6(row + 24, (uint)Marshal.ReadInt32(row, 40)); rp = Port(Marshal.ReadInt32(row, 44));
                            state = (uint)Marshal.ReadInt32(row, 48); pid = (uint)Marshal.ReadInt32(row, 52);
                            ts = module ? Marshal.ReadInt64(row, 56) : 0;
                        }
                        if (state == 2) { ra = fam == AF_INET ? "0.0.0.0" : "::"; rp = 0; }   // a listener has no remote end (the stack reports a stale one)
                        Dictionary<string, object> d = new Dictionary<string, object>();
                        d["InstanceID"] = la + "++" + lp + "++" + ra + "++" + rp;
                        d["EnabledDefault"] = 2; d["RequestedState"] = state == 2 ? 5 : 5; d["TransitioningToState"] = 12;
                        d["CreationTime"] = FileTimeToLocal(ts);
                        d["LocalAddress"] = la; d["LocalPort"] = lp; d["OwningProcess"] = pid;
                        d["AppliedSetting"] = state == 2 ? null : (object)0;
                        d["OffloadState"] = 0; d["RemoteAddress"] = ra; d["RemotePort"] = rp; d["State"] = state;
                        res.Add(d);
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return res;
        }

        public static List<Dictionary<string, object>> UdpEndpoints()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (uint fam in new uint[] { AF_INET6, AF_INET })
            {
                bool module = true;
                IntPtr buf = ReadTable(false, fam, 2);              // UDP_TABLE_OWNER_MODULE
                if (buf == IntPtr.Zero) { module = false; buf = ReadTable(false, fam, 1); }  // UDP_TABLE_OWNER_PID
                if (buf == IntPtr.Zero) continue;
                try
                {
                    uint n = (uint)Marshal.ReadInt32(buf);
                    int stride = fam == AF_INET ? (module ? 160 : 12) : (module ? 176 : 28);
                    int first = module ? 8 : 4;     // as for TCP: 64-bit timestamp in the module rows
                    for (uint i = 0; i < n; i++)
                    {
                        IntPtr row = buf + first + (int)(i * stride);
                        string la; ushort lp; uint pid; long ts;
                        if (fam == AF_INET)
                        {
                            la = Ipv4((uint)Marshal.ReadInt32(row)); lp = Port(Marshal.ReadInt32(row, 4)); pid = (uint)Marshal.ReadInt32(row, 8);
                            ts = module ? Marshal.ReadInt64(row, 16) : 0;
                        }
                        else
                        {
                            la = Ipv6(row, (uint)Marshal.ReadInt32(row, 16)); lp = Port(Marshal.ReadInt32(row, 20)); pid = (uint)Marshal.ReadInt32(row, 24);
                            ts = module ? Marshal.ReadInt64(row, 32) : 0;
                        }
                        Dictionary<string, object> d = new Dictionary<string, object>();
                        d["InstanceID"] = la + "++" + lp;
                        d["EnabledDefault"] = 2; d["RequestedState"] = 5; d["TransitioningToState"] = 12;
                        d["CreationTime"] = FileTimeToLocal(ts);
                        d["LocalAddress"] = la; d["LocalPort"] = lp; d["OwningProcess"] = pid;
                        res.Add(d);
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return res;
        }

        // ---- DnsClientServerAddress: one row per IP interface
        public static List<Dictionary<string, object>> DnsServers()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (Aa a in ReadAdapters())
            {
                uint idx = IndexOf(a);
                foreach (int fam in new int[] { AF_INET, AF_INET6 })
                {
                    uint ix = fam == AF_INET ? a.H.IfIndex : a.H.Ipv6IfIndex;
                    bool hasAddr = false;
                    foreach (Uni u in a.Unicast) if (u.Family == fam) hasAddr = true;
                    if (ix == 0 && !hasAddr) continue;
                    if (fam == AF_INET6 && !hasAddr && a.Dns6.Count == 0 && ix == 0) continue;
                    List<string> servers = fam == AF_INET ? a.Dns : a.Dns6;
                    Dictionary<string, object> d = new Dictionary<string, object>();
                    d["ElementName"] = a.Friendly; d["Name"] = idx.ToString(CultureInfo.InvariantCulture);
                    d["EnabledDefault"] = 2; d["EnabledState"] = 5; d["RequestedState"] = 12; d["TransitioningToState"] = 12;
                    d["CreationClassName"] = ""; d["SystemCreationClassName"] = "";
                    d["SystemName"] = fam.ToString(CultureInfo.InvariantCulture);
                    d["AccessContext"] = 0; d["AddressFamily"] = fam; d["InterfaceAlias"] = a.Friendly; d["InterfaceIndex"] = idx;
                    d["ServerAddresses"] = servers.ToArray();
                    res.Add(d);
                }
            }
            return res;
        }
    }
    // ------------------------------------------------------------------------------------------------ queries
    // The filtering the CDXML cmdlets get from their CIM query: per property the values are ORed, properties are ANDed,
    // strings are wildcard (LIKE) matches. Errors are returned, not thrown, and follow the measured Windows texts.
    public sealed class Query
    {
        readonly List<string> props = new List<string>();
        readonly List<object[]> vals = new List<object[]>();

        public void Add(string prop, object values)
        {
            List<object> l = new List<object>();
            PSObject po = values as PSObject; if (po != null) values = po.BaseObject;
            IEnumerable e = values as IEnumerable;
            if (e != null && !(values is string)) { foreach (object o in e) { PSObject p2 = o as PSObject; l.Add(p2 != null ? p2.BaseObject : o); } }
            else l.Add(values);
            props.Add(prop); vals.Add(l.ToArray());
        }

        static bool IsText(object v) { return v is string; }

        static string WildToLike(string s) { return s.Replace('*', '%').Replace('?', '_'); }

        static string Shown(object v)
        {
            if (v is Enum) return v.ToString();
            return Convert.ToString(v, CultureInfo.CurrentCulture);
        }

        static string WqlValue(object v)
        {
            if (v is string) return "LIKE '" + WildToLike((string)v) + "'";
            if (v is Enum) return "= " + Convert.ToUInt64(v, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
            if (v is bool) return "= " + (((bool)v) ? "TRUE" : "FALSE");
            if (v is DateTime) return "= '" + ((DateTime)v).ToString("yyyyMMddHHmmss.ffffff", CultureInfo.InvariantCulture) + "'";
            return "= " + Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        static bool Equal(object item, object want)
        {
            if (item == null) return false;
            if (want is string)
            {
                string s = item as string; if (s == null) s = Convert.ToString(item, CultureInfo.InvariantCulture);
                return new WildcardPattern((string)want, WildcardOptions.IgnoreCase | WildcardOptions.CultureInvariant).IsMatch(s);
            }
            if (want is Enum) { try { return Convert.ToUInt64(item, CultureInfo.InvariantCulture) == Convert.ToUInt64(want, CultureInfo.InvariantCulture); } catch (Exception) { return false; } }
            if (want is bool) return item is bool && (bool)item == (bool)want;
            if (want is TimeSpan) return item is TimeSpan && (TimeSpan)item == (TimeSpan)want;
            if (want is DateTime) return item is DateTime && (DateTime)item == (DateTime)want;
            try { return Convert.ToDecimal(item, CultureInfo.InvariantCulture) == Convert.ToDecimal(want, CultureInfo.InvariantCulture); } catch (Exception) { return false; }
        }

        public List<Dictionary<string, object>> Run(IEnumerable source, string cls, List<ErrorRecord> errors)
        {
            List<Dictionary<string, object>> items = new List<Dictionary<string, object>>();
            foreach (object o in source)
            {
                object b = o; PSObject po = b as PSObject; if (po != null) b = po.BaseObject;
                items.Add((Dictionary<string, object>)b);
            }
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (Dictionary<string, object> it in items)
            {
                bool ok = true;
                for (int i = 0; i < props.Count && ok; i++)
                {
                    object v; it.TryGetValue(props[i], out v);
                    bool any = false;
                    foreach (object w in vals[i]) if (Equal(v, w)) { any = true; break; }
                    ok = any;
                }
                if (ok) res.Add(it);
            }
            if (res.Count > 0 && props.Count != 1) return res;
            if (props.Count == 1)
            {
                // one property: every exact value that matched nothing is reported (wildcards never are)
                foreach (object w in vals[0])
                {
                    if (w is string && WildcardPattern.ContainsWildcardCharacters((string)w)) continue;
                    bool found = false;
                    foreach (Dictionary<string, object> it in res) { object v; it.TryGetValue(props[0], out v); if (Equal(v, w)) { found = true; break; } }
                    if (!found) errors.Add(Errors.NotFoundValue(cls, props[0], w, Shown(w)));
                }
            }
            else if (props.Count > 1 && res.Count == 0)
            {
                StringBuilder sb = new StringBuilder("SELECT * FROM " + cls + "  WHERE ");
                for (int i = 0; i < props.Count; i++)
                {
                    if (i > 0) sb.Append(" AND ");
                    sb.Append('(');
                    for (int j = 0; j < vals[i].Length; j++)
                    {
                        if (j > 0) sb.Append(" OR ");
                        sb.Append('(').Append(props[i]).Append(' ').Append(WqlValue(vals[i][j])).Append(')');
                    }
                    sb.Append(')');
                }
                errors.Add(Errors.NotFoundQuery(cls, sb.ToString()));
            }
            return res;
        }
    }

    public static class Errors
    {
        // The Windows cmdlets throw Microsoft.PowerShell.Cmdletization.Cim.CimJobException; it is built through its internal
        // factory so that Exception.GetType() and CategoryInfo.Reason read the same. Falls back to a plain exception.
        static Exception Cim(string message, string errorId, ErrorCategory cat)
        {
            try
            {
                Type t = Type.GetType("Microsoft.PowerShell.Cmdletization.Cim.CimJobException, Microsoft.PowerShell.Commands.Management");
                MethodInfo m = t.GetMethod("CreateWithoutJobContext", BindingFlags.NonPublic | BindingFlags.Static);
                return (Exception)m.Invoke(null, new object[] { message, errorId, cat, null });
            }
            catch (Exception) { return new InvalidOperationException(message); }
        }

        public static ErrorRecord NotFoundValue(string cls, string prop, object target, string shown)
        {
            string id = "CmdletizationQuery_NotFound_" + prop;
            string msg = "No " + cls + " objects found with property '" + prop + "' equal to '" + shown + "'.  Verify the value of the property and retry.";
            return new ErrorRecord(Cim(msg, id, ErrorCategory.ObjectNotFound), id, ErrorCategory.ObjectNotFound, target);
        }

        public static ErrorRecord NotFoundQuery(string cls, string wql)
        {
            string id = "CmdletizationQuery_NotFound";
            string msg = "No matching " + cls + " objects found by CIM query for instances of the ROOT/StandardCimv2/" + cls +
                " class on the  CIM server: " + wql + ". Verify query parameters and retry.";
            return new ErrorRecord(Cim(msg, id, ErrorCategory.ObjectNotFound), id, ErrorCategory.ObjectNotFound, cls);
        }

        public static ErrorRecord InvalidStore(string value)
        {
            Exception e = new InvalidOperationException("Invalid parameter PolicyStore " + value + "\n");
            return new ErrorRecord(e, "Windows System Error 87", ErrorCategory.InvalidArgument, "MSFT_NetIPAddress");
        }
    }
}

// Result objects of Get-NetIPConfiguration and Test-NetConnection: global-namespace types like the Windows ones, so the
// type name (and so the default views) read NetIPConfiguration and TestNetConnectionResult.
public class NetIPConfiguration
{
    public string ComputerName { get; set; }
    public string InterfaceAlias { get; set; }
    public int InterfaceIndex { get; set; }
    public string InterfaceDescription { get; set; }
    public int CompartmentId { get; set; }
    public object NetAdapter { get; set; }
    public object NetCompartment { get; set; }
    public object NetIPv6Interface { get; set; }
    public object NetIPv4Interface { get; set; }
    public object NetProfile { get; set; }
    public object[] AllIPAddresses { get; set; }
    public object[] IPv6Address { get; set; }
    public object[] IPv6TemporaryAddress { get; set; }
    public object[] IPv6LinkLocalAddress { get; set; }
    public object[] IPv4Address { get; set; }
    public object[] IPv6DefaultGateway { get; set; }
    public object[] IPv4DefaultGateway { get; set; }
    public object[] DNSServer { get; set; }
    public bool Detailed { get; set; }
}

public class TestNetConnectionResult
{
    public string ComputerName { get; set; }
    public System.Net.IPAddress RemoteAddress { get; set; }
    public System.Net.IPAddress[] ResolvedAddresses { get; set; }
    public bool PingSucceeded { get; set; }
    public System.Net.NetworkInformation.PingReply PingReplyDetails { get; set; }
    public object TcpClientSocket { get; set; }
    public bool TcpTestSucceeded { get; set; }
    public uint RemotePort { get; set; }
    public string[] TraceRoute { get; set; }
    public bool Detailed { get; set; }
    public string InterfaceAlias { get; set; }
    public uint InterfaceIndex { get; set; }
    public string InterfaceDescription { get; set; }
    public object NetAdapter { get; set; }
    public object NetRoute { get; set; }
    public object SourceAddress { get; set; }
    public bool NameResolutionSucceeded { get; set; }
    public object[] BasicNameResolution { get; set; }
    public object[] LLMNRNetbiosRecords { get; set; }
    public object[] DNSOnlyRecords { get; set; }
    public object AllNameResolutionResults { get; set; }
    public bool IsAdmin { get; set; }
    public string NetworkIsolationContext { get; set; }
    public object MatchingIPsecRules { get; set; }
}
