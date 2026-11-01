// Storage module for ReactOS-Nitro (clean-room): native helper, object builder and query filter.
// Data comes from kernel32 volume calls and the disk/partition/volume IOCTLs; the output objects carry the Windows
// MSFT_Volume / MSFT_Disk / MSFT_Partition / MSFT_PhysicalDisk shapes (names, order, types, type-name chains) measured on Windows 10.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Nitro.Storage
{
    // The CLR object behind the CIM-shaped PSObjects: a non-PSCustomObject base keeps Select-Object from copying them.
    public sealed class StorageObject
    {
        internal string ClassName, ObjectId;   // internal: PowerShell would expose public fields as properties
        public override string ToString()
        {
            string s = "\"" + ObjectId;
            if (s.Length > 40) s = s.Substring(0, 40) + "...";
            return ClassName + " (ObjectId = " + s + ")";
        }
    }

    public static class Builder
    {
        const string P = "Microsoft.Management.Infrastructure.CimInstance";
        sealed class ClassInfo { public string[] TypeNames, Names, Types; }
        const string Common = "ObjectId:s,PassThroughClass:s,PassThroughIds:s,PassThroughNamespace:s,PassThroughServer:s,UniqueId:s";
        static readonly Dictionary<string, ClassInfo> classes = Build();

        static string[] Chain(string ns, params string[] cls)
        {
            List<string> l = new List<string>();
            foreach (string c in cls) l.Add(P + "#" + ns + "/" + c);
            foreach (string c in cls) l.Add(P + "#" + c);
            l.Add(P); l.Add("System.Object");
            return l.ToArray();
        }

        static ClassInfo Info(string[] names, string spec)
        {
            ClassInfo ci = new ClassInfo(); ci.TypeNames = names;
            List<string> n = new List<string>(), t = new List<string>();
            foreach (string m in spec.Split(',')) { string[] f = m.Split(':'); n.Add(f[0]); t.Add(f[1]); }
            ci.Names = n.ToArray(); ci.Types = t.ToArray();
            return ci;
        }

        // member types: s string, e display string of a CIM enum, ea array of those, sa string[], b bool, c char, u16/u32/u64 unsigned,
        // @Name alias of another member
        static Dictionary<string, ClassInfo> Build()
        {
            Dictionary<string, ClassInfo> d = new Dictionary<string, ClassInfo>();
            const string ns = "ROOT/Microsoft/Windows/Storage";
            d["MSFT_Volume"] = Info(Chain(ns, "MSFT_Volume", "MSFT_StorageObject"),
                "OperationalStatus:e,HealthStatus:e,DriveType:e,FileSystemType:e,DedupMode:e," + Common +
                ",AllocationUnitSize:u32,DriveLetter:c,FileSystem:s,FileSystemLabel:s,Path:s,Size:u64,SizeRemaining:u64");
            d["MSFT_Disk"] = Info(Chain(ns, "MSFT_Disk", "MSFT_StorageObject"),
                "DiskNumber:@Number,PartitionStyle:e,ProvisioningType:e,OperationalStatus:e,HealthStatus:e,BusType:e,UniqueIdFormat:e,OfflineReason:e," + Common +
                ",AdapterSerialNumber:s,AllocatedSize:u64,BootFromDisk:b,FirmwareVersion:s,FriendlyName:s,Guid:s,IsBoot:b,IsClustered:b,IsHighlyAvailable:b," +
                "IsOffline:b,IsReadOnly:b,IsScaleOut:b,IsSystem:b,LargestFreeExtent:u64,Location:s,LogicalSectorSize:u32,Manufacturer:s,Model:s,Number:u32," +
                "NumberOfPartitions:u32,Path:s,PhysicalSectorSize:u32,SerialNumber:s,Signature:u32,Size:u64");
            d["MSFT_Partition"] = Info(Chain(ns, "MSFT_Partition", "MSFT_StorageObject"),
                "OperationalStatus:e,Type:e,DiskPath:s," + Common +
                ",AccessPaths:sa,DiskId:s,DiskNumber:u32,DriveLetter:c,GptType:s,Guid:s,IsActive:b,IsBoot:b,IsDAX:b,IsHidden:b,IsOffline:b,IsReadOnly:b," +
                "IsShadowCopy:b,IsSystem:b,MbrType:u16,NoDefaultDriveLetter:b,Offset:u64,PartitionNumber:u32,Size:u64,TransitionState:u16");
            d["MSFT_PhysicalDisk"] = Info(Chain(ns, "MSFT_PhysicalDisk", "MSFT_StorageFaultDomain", "MSFT_StorageObject"),
                "ClassName:s,Usage:e,OperationalStatus:e,UniqueIdFormat:e,HealthStatus:e,BusType:e,CannotPoolReason:e,SupportedUsages:ea,MediaType:e,SpindleSpeed:u32," + Common +
                ",Description:s,FriendlyName:s,Manufacturer:s,Model:s,OperationalDetails:sa,PhysicalLocation:s,SerialNumber:s,AdapterSerialNumber:s," +
                "AllocatedSize:u64,CanPool:b,DeviceId:s,EnclosureNumber:u16,FirmwareVersion:s,IsIndicationEnabled:b,IsPartial:b,LogicalSectorSize:u64," +
                "OtherCannotPoolReasonDescription:s,PartNumber:s,PhysicalSectorSize:u64,Size:u64,SlotNumber:u16,SoftwareVersion:s,StoragePoolUniqueId:s,VirtualDiskFootprint:u64");
            // the measured physical disk chain starts with a lower-case namespace
            d["MSFT_PhysicalDisk"].TypeNames[0] = P + "#root/microsoft/windows/storage/MSFT_PhysicalDisk";
            return d;
        }

        static object Coerce(object v, string t)
        {
            if (v == null) return null;
            PSObject po = v as PSObject; if (po != null) v = po.BaseObject;
            try
            {
                switch (t)
                {
                    case "b": return v is bool ? v : (object)Convert.ToBoolean(v, CultureInfo.InvariantCulture);
                    case "c": return v is char ? v : (object)Convert.ToChar(v, CultureInfo.InvariantCulture);
                    case "u16": return v is ushort ? v : (object)Convert.ToUInt16(v, CultureInfo.InvariantCulture);
                    case "u32": return v is uint ? v : (object)Convert.ToUInt32(v, CultureInfo.InvariantCulture);
                    case "u64": return v is ulong ? v : (object)Convert.ToUInt64(v, CultureInfo.InvariantCulture);
                    case "sa": { if (v is string[]) return v; List<string> l = new List<string>(); foreach (object o in (IEnumerable)v) l.Add(Convert.ToString(o, CultureInfo.InvariantCulture)); return l.ToArray(); }
                    case "ea": { if (v is object[]) return v; List<object> l = new List<object>(); foreach (object o in (IEnumerable)v) l.Add(o); return l.ToArray(); }
                    default: return v;
                }
            }
            catch (Exception) { return v; }
        }

        public static PSObject Create(string cls, IDictionary values)
        {
            ClassInfo ci = classes[cls];
            StorageObject so = new StorageObject(); so.ClassName = cls;
            so.ObjectId = values.Contains("ObjectId") ? Convert.ToString(values["ObjectId"], CultureInfo.InvariantCulture) : "";
            PSObject o = new PSObject(so);
            o.TypeNames.Clear();
            foreach (string t in ci.TypeNames) o.TypeNames.Add(t);
            for (int i = 0; i < ci.Names.Length; i++)
            {
                if (ci.Types[i].StartsWith("@")) { o.Members.Add(new PSAliasProperty(ci.Names[i], ci.Types[i].Substring(1))); continue; }
                object v = values.Contains(ci.Names[i]) ? values[ci.Names[i]] : null;
                o.Members.Add(new PSNoteProperty(ci.Names[i], Coerce(v, ci.Types[i])));
            }
            o.Members.Add(new PSNoteProperty("PSComputerName", null));
            return o;
        }
    }

    // Filters the items by property values (strings with wildcards when asked, case-insensitive) and builds the "not found"
    // errors the Windows cmdlets write: one per unmatched exact value when a single property is queried, else one query error.
    public sealed class Query
    {
        readonly List<string> props = new List<string>();
        readonly List<object[]> vals = new List<object[]>();
        readonly List<bool> wild = new List<bool>();

        public void Add(string prop, object values, bool wildcards)
        {
            List<object> l = new List<object>();
            PSObject po = values as PSObject; if (po != null) values = po.BaseObject;
            IEnumerable e = values as IEnumerable;
            if (e != null && !(values is string)) { foreach (object o in e) { PSObject p2 = o as PSObject; l.Add(p2 != null ? p2.BaseObject : o); } }
            else l.Add(values);
            props.Add(prop); vals.Add(l.ToArray()); wild.Add(wildcards);
        }

        static bool Equal(object item, object want, bool wildcards)
        {
            if (item == null || want == null) return false;
            if (want is string)
            {
                string s = item as string; if (s == null) s = Convert.ToString(item, CultureInfo.InvariantCulture);
                if (wildcards) return new WildcardPattern((string)want, WildcardOptions.IgnoreCase | WildcardOptions.CultureInvariant).IsMatch(s);
                return string.Equals(s, (string)want, StringComparison.OrdinalIgnoreCase);
            }
            if (want is char) return item is char && char.ToUpperInvariant((char)item) == char.ToUpperInvariant((char)want);
            if (want is bool) return item is bool && (bool)item == (bool)want;
            try { return Convert.ToDecimal(item, CultureInfo.InvariantCulture) == Convert.ToDecimal(want, CultureInfo.InvariantCulture); } catch (Exception) { return false; }
        }

        static string Shown(object v) { return Convert.ToString(v, CultureInfo.InvariantCulture); }

        static string WqlValue(object v)
        {
            if (v is string) return "LIKE '" + ((string)v).Replace('*', '%').Replace('?', '_') + "'";
            if (v is bool) return "= " + (((bool)v) ? "TRUE" : "FALSE");
            if (v is char) return "= '" + v + "'";
            return "= " + Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        public List<Dictionary<string, object>> Run(IEnumerable source, string cls, bool reportMissing, List<ErrorRecord> errors)
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (object o in source)
            {
                object b = o; PSObject po = b as PSObject; if (po != null) b = po.BaseObject;
                Dictionary<string, object> it = (Dictionary<string, object>)b;
                bool ok = true;
                for (int i = 0; i < props.Count && ok; i++)
                {
                    object v; it.TryGetValue(props[i], out v);
                    bool any = false;
                    foreach (object w in vals[i]) if (Equal(v, w, wild[i])) { any = true; break; }
                    ok = any;
                }
                if (ok) res.Add(it);
            }
            if (!reportMissing) return res;
            if (props.Count == 1)
            {
                foreach (object w in vals[0])
                {
                    if (w is string && wild[0] && WildcardPattern.ContainsWildcardCharacters((string)w)) continue;
                    bool found = false;
                    foreach (Dictionary<string, object> it in res) { object v; it.TryGetValue(props[0], out v); if (Equal(v, w, wild[0])) { found = true; break; } }
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
        // Windows throws Microsoft.PowerShell.Cmdletization.Cim.CimJobException; it is built through its internal factory
        // so Exception.GetType() and CategoryInfo.Reason read the same. Falls back to a plain exception.
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
            string msg = "No matching " + cls + " objects found by CIM query for instances of the ROOT/Microsoft/Windows/Storage/" + cls +
                " class on the  CIM server: " + wql + ". Verify query parameters and retry.";
            return new ErrorRecord(Cim(msg, id, ErrorCategory.ObjectNotFound), id, ErrorCategory.ObjectNotFound, cls);
        }
    }

    public static class Native
    {
        const uint GENERIC_READ = 0x80000000, SHARE_RW = 3, OPEN_EXISTING = 3;
        static readonly IntPtr Invalid = new IntPtr(-1);
        const uint IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x700A0, IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x70050, IOCTL_DISK_GET_DISK_ATTRIBUTES = 0x700F0,
            IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400, IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x560000,
            IOCTL_SCSI_GET_ADDRESS = 0x41018;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inb, uint inLen, byte[] outb, uint outLen, out uint ret, IntPtr ov);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern uint SetErrorMode(uint mode);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstVolumeW(StringBuilder name, int len);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool FindNextVolumeW(IntPtr h, StringBuilder name, int len);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool FindVolumeClose(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetVolumePathNamesForVolumeNameW(string vol, char[] buf, uint len, out uint ret);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetVolumeNameForVolumeMountPointW(string mp, StringBuilder name, uint len);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetVolumePathNameW(string file, StringBuilder path, uint len);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetLogicalDriveStringsW(uint len, char[] buf);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumeInformationW(string root, StringBuilder label, uint labelLen, out uint serial, out uint maxComp, out uint flags, StringBuilder fs, uint fsLen);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetDiskFreeSpaceExW(string dir, out ulong avail, out ulong total, out ulong free);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetDiskFreeSpaceW(string root, out uint spc, out uint bps, out uint freeClusters, out uint clusters);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern uint GetDriveTypeW(string root);
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr SetupDiGetClassDevsW(ref Guid g, string enumerator, IntPtr parent, uint flags);
        [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr info, ref Guid g, uint index, byte[] data);
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SetupDiGetDeviceInterfaceDetailW(IntPtr set, byte[] data, byte[] detail, uint size, out uint req, IntPtr info);
        [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

        static readonly string[] BusTypes = { "Unknown", "SCSI", "ATAPI", "ATA", "1394", "SSA", "Fibre Channel", "USB", "RAID", "iSCSI", "SAS", "SATA", "SD", "MMC", "Virtual", "File Backed Virtual", "Spaces", "NVMe", "SCM", "UFS" };
        static readonly string[] DiskStyles = { "RAW", "MBR", "GPT" };
        static readonly string[] DriveTypes = { "Unknown", "Invalid Root Path", "Removable", "Fixed", "Remote", "CD-ROM", "RAM Disk" };

        // ---------------------------------------------------------------- helpers
        static string machineId;
        static string MachineId()
        {
            if (machineId != null) return machineId;
            string g = null;
            try { g = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string; } catch (Exception) { }
            Guid parsed;
            if (g == null || !Guid.TryParse(g, out parsed)) parsed = HashGuid(Environment.MachineName);
            machineId = parsed.ToString("D").ToLowerInvariant();
            return machineId;
        }

        static Guid HashGuid(string s)
        {
            using (MD5 md5 = MD5.Create()) return new Guid(md5.ComputeHash(Encoding.UTF8.GetBytes(s)));
        }

        static string ObjectId(string cls, string tag, string key)
        {
            return "{1}\\\\" + Environment.MachineName + "\\root/Microsoft/Windows/Storage/Providers_v2\\" + cls + ".ObjectId=\"{" + MachineId() + "}:" + tag + ":" + key + "\"";
        }

        static string Trim(string s) { return s == null ? null : s.Trim(); }
        static string NullIfEmpty(string s) { return string.IsNullOrEmpty(s) ? null : s; }

        static IntPtr Open(string path)
        {
            IntPtr h = CreateFileW(path, GENERIC_READ, SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h == Invalid) h = CreateFileW(path, 0, SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            return h;
        }

        static byte[] Ioctl(IntPtr h, uint code, byte[] input, int outSize)
        {
            for (int tries = 0; tries < 6; tries++)
            {
                byte[] buf = new byte[outSize]; uint ret;
                if (DeviceIoControl(h, code, input, (uint)(input == null ? 0 : input.Length), buf, (uint)buf.Length, out ret, IntPtr.Zero))
                {
                    if (ret == buf.Length) return buf;
                    byte[] r = new byte[ret]; Array.Copy(buf, r, (int)ret); return r;
                }
                int err = Marshal.GetLastWin32Error();
                if (err != 122 && err != 234) return null;
                outSize *= 4;
            }
            return null;
        }

        static byte[] QueryProperty(IntPtr h, uint id, int size)
        {
            byte[] q = new byte[12]; BitConverter.GetBytes(id).CopyTo(q, 0);   // PropertyId, QueryType = standard (0)
            return Ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, q, size);
        }

        // some miniports return the serial number as a hex string of its ASCII bytes
        static string DecodeSerial(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            string t = s.Trim();
            if (t.Length < 4 || t.Length % 2 != 0) return s;
            byte[] b = new byte[t.Length / 2];
            for (int i = 0; i < b.Length; i++)
            {
                int hi = Uri.IsHexDigit(t[2 * i]) && Uri.IsHexDigit(t[2 * i + 1]) ? Convert.ToInt32(t.Substring(2 * i, 2), 16) : -1;
                if (hi < 0x20 || hi > 0x7e) return s;
                b[i] = (byte)hi;
            }
            return Encoding.ASCII.GetString(b).Trim();
        }

        static string AnsiAt(byte[] b, int offset)
        {
            if (offset <= 0 || offset >= b.Length) return null;
            int e = offset; while (e < b.Length && b[e] != 0) e++;
            return Encoding.ASCII.GetString(b, offset, e - offset);
        }

        static string EnumName(string[] names, uint v, string def) { return v < names.Length && names[v] != null ? names[v] : def; }

        // ---------------------------------------------------------------- volumes
        sealed class Extent { public uint Disk; public ulong Offset, Length; }
        sealed class VolInfo
        {
            public string Path; public List<string> MountPoints = new List<string>(); public List<Extent> Extents = new List<Extent>();
            public char Letter; public uint DriveType; public bool HasMedia;
            public string Label, Fs; public ulong Size, Free; public uint Cluster;
        }

        static List<string> VolumePaths()
        {
            List<string> l = new List<string>();
            StringBuilder sb = new StringBuilder(260);
            IntPtr h = FindFirstVolumeW(sb, 260);
            if (h != Invalid)
            {
                do { l.Add(sb.ToString()); } while (FindNextVolumeW(h, sb, 260));
                FindVolumeClose(h);
            }
            if (l.Count == 0)
            {
                // fallback: one volume per mounted drive letter
                char[] buf = new char[512]; uint n = GetLogicalDriveStringsW((uint)buf.Length, buf);
                foreach (string root in new string(buf, 0, (int)n).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    StringBuilder v = new StringBuilder(260);
                    if (GetVolumeNameForVolumeMountPointW(root, v, 260)) l.Add(v.ToString()); else l.Add(root);
                }
            }
            return l;
        }

        static List<string> MountPoints(string vol)
        {
            List<string> l = new List<string>();
            char[] buf = new char[1024]; uint ret;
            if (!GetVolumePathNamesForVolumeNameW(vol, buf, (uint)buf.Length, out ret))
            {
                if (vol.Length == 3 && vol[1] == ':') l.Add(vol);
                return l;
            }
            foreach (string s in new string(buf, 0, (int)ret).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries)) l.Add(s);
            return l;
        }

        static List<Extent> VolumeExtents(string vol)
        {
            List<Extent> l = new List<Extent>();
            string dev = vol.EndsWith("\\") ? vol.Substring(0, vol.Length - 1) : vol;
            IntPtr h = Open(dev);
            if (h == Invalid) return l;
            try
            {
                byte[] b = Ioctl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, null, 64);
                if (b == null || b.Length < 8) return l;
                uint n = BitConverter.ToUInt32(b, 0);
                for (int i = 0; i < n && 8 + (i + 1) * 24 <= b.Length; i++)
                {
                    Extent e = new Extent(); int o = 8 + i * 24;
                    e.Disk = BitConverter.ToUInt32(b, o); e.Offset = BitConverter.ToUInt64(b, o + 8); e.Length = BitConverter.ToUInt64(b, o + 16);
                    l.Add(e);
                }
            }
            finally { CloseHandle(h); }
            return l;
        }

        static List<VolInfo> VolInfos()
        {
            List<VolInfo> res = new List<VolInfo>();
            uint oldMode = SetErrorMode(1);   // SEM_FAILCRITICALERRORS: no dialogs for empty drives
            try
            {
                foreach (string vp in VolumePaths())
                {
                    VolInfo v = new VolInfo(); v.Path = vp;
                    v.MountPoints = MountPoints(vp);
                    foreach (string m in v.MountPoints)
                        if (m.Length == 3 && m[1] == ':' && m[2] == '\\') { v.Letter = char.ToUpperInvariant(m[0]); break; }
                    v.DriveType = GetDriveTypeW(vp);
                    StringBuilder label = new StringBuilder(261), fs = new StringBuilder(261); uint serial, maxc, flags;
                    v.HasMedia = GetVolumeInformationW(vp, label, 261, out serial, out maxc, out flags, fs, 261);
                    if (v.HasMedia) { v.Label = label.ToString(); v.Fs = fs.ToString(); }
                    ulong avail, total, free;
                    if (GetDiskFreeSpaceExW(vp, out avail, out total, out free)) { v.Size = total; v.Free = free; }
                    uint spc, bps, fc, tc;
                    if (GetDiskFreeSpaceW(vp, out spc, out bps, out fc, out tc)) v.Cluster = spc * bps;
                    if (v.DriveType == 3 || v.DriveType == 2) v.Extents = VolumeExtents(vp);
                    res.Add(v);
                }
            }
            finally { SetErrorMode(oldMode); }
            return res;
        }

        static string FsType(string fs)
        {
            switch ((fs ?? "").ToUpperInvariant())
            {
                case "NTFS": return "NTFS";
                case "FAT32": return "FAT32";
                case "FAT": return "FAT";
                case "REFS": return "ReFS";
                case "EXT2": return "EXT2";
                case "EXT3": return "EXT3";
                default: return null;
            }
        }

        public static List<Dictionary<string, object>> Volumes()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (VolInfo v in VolInfos())
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["OperationalStatus"] = v.HasMedia ? "OK" : "Unknown";
                d["HealthStatus"] = v.HasMedia ? "Healthy" : "Unknown";
                d["DriveType"] = EnumName(DriveTypes, v.DriveType, "Unknown");
                d["FileSystemType"] = v.HasMedia ? FsType(v.Fs) : "Unknown";
                d["DedupMode"] = "NotAvailable";
                d["ObjectId"] = ObjectId("WSP_Volume", "VO", v.Path);
                d["UniqueId"] = v.Path;
                d["AllocationUnitSize"] = v.Cluster;
                d["DriveLetter"] = v.Letter == '\0' ? (object)null : v.Letter;
                d["FileSystem"] = v.HasMedia ? v.Fs : null;
                d["FileSystemLabel"] = v.HasMedia ? v.Label : null;
                d["Path"] = v.Path;
                d["Size"] = v.Size;
                d["SizeRemaining"] = v.Free;
                res.Add(d);
            }
            return res;
        }

        // the volume that holds a file path (GetVolumePathName), as a volume GUID path
        public static string VolumeOfFile(string file)
        {
            StringBuilder root = new StringBuilder(1024);
            if (!GetVolumePathNameW(file, root, 1024)) return null;
            StringBuilder vol = new StringBuilder(260);
            return GetVolumeNameForVolumeMountPointW(root.ToString(), vol, 260) ? vol.ToString() : null;
        }

        // ---------------------------------------------------------------- disks and partitions
        sealed class Part
        {
            public ulong Offset, Length, Attr; public uint Number; public byte MbrType; public bool Boot;
            public string GptType, Guid;
        }
        sealed class Layout { public int Style = 0; public uint Signature; public string Guid; public List<Part> Parts = new List<Part>(); }
        sealed class DiskInfo
        {
            public uint Number; public string Path, Vendor, Product, Revision, Serial, Location; public uint Bus, LogicalSector = 512, PhysicalSector = 512;
            public ulong Size; public Layout Layout; public bool Offline, ReadOnly, Seek = true, SeekKnown;
        }

        static Layout ReadLayout(IntPtr h)
        {
            byte[] b = Ioctl(h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, null, 4096);
            if (b == null || b.Length < 48) return null;
            Layout l = new Layout();
            uint style = BitConverter.ToUInt32(b, 0), count = BitConverter.ToUInt32(b, 4);
            l.Style = style == 0 ? 1 : style == 1 ? 2 : 0;   // PARTITION_STYLE MBR=0 GPT=1 RAW=2 -> MSFT_Disk RAW=0 MBR=1 GPT=2
            if (style == 0) l.Signature = BitConverter.ToUInt32(b, 8);
            else if (style == 1)
            {
                byte[] g = new byte[16]; Array.Copy(b, 8, g, 0, 16);
                l.Guid = "{" + new Guid(g).ToString("D").ToLowerInvariant() + "}";
            }
            for (int i = 0; i < count && 48 + (i + 1) * 144 <= b.Length; i++)
            {
                int o = 48 + i * 144;
                Part p = new Part();
                p.Offset = BitConverter.ToUInt64(b, o + 8); p.Length = BitConverter.ToUInt64(b, o + 16); p.Number = BitConverter.ToUInt32(b, o + 24);
                uint ps = BitConverter.ToUInt32(b, o);
                if (ps == 0) { p.MbrType = b[o + 32]; p.Boot = b[o + 33] != 0; }
                else if (ps == 1)
                {
                    byte[] t = new byte[16], id = new byte[16]; Array.Copy(b, o + 32, t, 0, 16); Array.Copy(b, o + 48, id, 0, 16);
                    p.GptType = "{" + new Guid(t).ToString("D").ToLowerInvariant() + "}";
                    p.Guid = "{" + new Guid(id).ToString("D").ToLowerInvariant() + "}";
                    p.Attr = BitConverter.ToUInt64(b, o + 64);
                }
                if (p.Number != 0 && p.Length != 0) l.Parts.Add(p);
            }
            return l;
        }

        static Dictionary<uint, string> DiskInterfacePaths()
        {
            Dictionary<uint, string> map = new Dictionary<uint, string>();
            try
            {
                Guid g = new Guid("53f56307-b6bf-11d0-94f2-00a0c91efb8b");
                IntPtr set = SetupDiGetClassDevsW(ref g, null, IntPtr.Zero, 0x12);   // DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
                if (set == Invalid || set == IntPtr.Zero) return map;
                try
                {
                    int ifSize = IntPtr.Size == 8 ? 32 : 28;
                    for (uint i = 0; i < 256; i++)
                    {
                        byte[] data = new byte[ifSize]; BitConverter.GetBytes((uint)ifSize).CopyTo(data, 0);
                        if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref g, i, data)) break;
                        uint req;
                        SetupDiGetDeviceInterfaceDetailW(set, data, null, 0, out req, IntPtr.Zero);
                        if (req == 0) continue;
                        byte[] detail = new byte[req]; BitConverter.GetBytes((uint)(IntPtr.Size == 8 ? 8 : 6)).CopyTo(detail, 0);
                        if (!SetupDiGetDeviceInterfaceDetailW(set, data, detail, req, out req, IntPtr.Zero)) continue;
                        string path = Encoding.Unicode.GetString(detail, 4, detail.Length - 4);
                        int z = path.IndexOf('\0'); if (z >= 0) path = path.Substring(0, z);
                        IntPtr h = Open(path);
                        if (h == Invalid) continue;
                        try
                        {
                            byte[] dn = Ioctl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, null, 12);
                            if (dn != null && dn.Length >= 12 && !map.ContainsKey(BitConverter.ToUInt32(dn, 4))) map[BitConverter.ToUInt32(dn, 4)] = path.ToLowerInvariant();
                        }
                        finally { CloseHandle(h); }
                    }
                }
                finally { SetupDiDestroyDeviceInfoList(set); }
            }
            catch (Exception) { }
            return map;
        }

        static List<DiskInfo> DiskInfos()
        {
            List<DiskInfo> res = new List<DiskInfo>();
            Dictionary<uint, string> paths = null;
            for (uint n = 0; n < 32; n++)
            {
                IntPtr h = Open("\\\\.\\PhysicalDrive" + n);
                if (h == Invalid) continue;
                try
                {
                    DiskInfo d = new DiskInfo(); d.Number = n;
                    byte[] geo = Ioctl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, null, 256);
                    if (geo != null && geo.Length >= 32)
                    {
                        d.LogicalSector = BitConverter.ToUInt32(geo, 20); d.PhysicalSector = d.LogicalSector;
                        d.Size = BitConverter.ToUInt64(geo, 24);
                    }
                    byte[] dev = QueryProperty(h, 0, 1024);
                    if (dev != null && dev.Length >= 36)
                    {
                        d.Vendor = AnsiAt(dev, BitConverter.ToInt32(dev, 12)); d.Product = AnsiAt(dev, BitConverter.ToInt32(dev, 16));
                        d.Revision = AnsiAt(dev, BitConverter.ToInt32(dev, 20)); d.Serial = DecodeSerial(AnsiAt(dev, BitConverter.ToInt32(dev, 24)));
                        d.Bus = BitConverter.ToUInt32(dev, 28);
                    }
                    byte[] al = QueryProperty(h, 6, 64);   // StorageAccessAlignmentProperty
                    if (al != null && al.Length >= 28)
                    {
                        uint ls = BitConverter.ToUInt32(al, 16), ph = BitConverter.ToUInt32(al, 20);
                        if (ls != 0) d.LogicalSector = ls;
                        if (ph != 0) d.PhysicalSector = ph;
                    }
                    byte[] sk = QueryProperty(h, 7, 64);   // StorageDeviceSeekPenaltyProperty
                    if (sk != null && sk.Length >= 9) { d.SeekKnown = true; d.Seek = sk[8] != 0; }
                    byte[] sa = Ioctl(h, IOCTL_SCSI_GET_ADDRESS, null, 8);
                    if (sa != null && sa.Length >= 8)
                        d.Location = "Integrated : Adapter " + sa[4] + " : Port " + sa[5] + " : Target " + sa[6] + " : LUN " + sa[7];
                    byte[] at = Ioctl(h, IOCTL_DISK_GET_DISK_ATTRIBUTES, null, 16);
                    if (at != null && at.Length >= 16) { ulong a = BitConverter.ToUInt64(at, 8); d.Offline = (a & 1) != 0; d.ReadOnly = (a & 2) != 0; }
                    d.Layout = ReadLayout(h);
                    if (paths == null) paths = DiskInterfacePaths();
                    string p; d.Path = paths.TryGetValue(n, out p) ? p : "\\\\?\\PhysicalDrive" + n;
                    res.Add(d);
                }
                finally { CloseHandle(h); }
            }
            return res;
        }

        static string DiskUniqueId(DiskInfo d)
        {
            string s = Trim(d.Serial);
            if (!string.IsNullOrEmpty(s)) return s;
            if (d.Layout != null && d.Layout.Guid != null) return d.Layout.Guid;
            if (d.Layout != null && d.Layout.Signature != 0) return d.Layout.Signature.ToString("X8", CultureInfo.InvariantCulture);
            return "PhysicalDrive" + d.Number;
        }

        static string FriendlyName(DiskInfo d) { return NullIfEmpty(((Trim(d.Vendor) ?? "") + " " + (Trim(d.Product) ?? "")).Trim()); }

        static string BootVolume() { return VolumeOfFile(Environment.GetFolderPath(Environment.SpecialFolder.Windows)); }

        const string GptSystem = "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}", GptReserved = "{e3c9e316-0b5c-4db8-817d-f92df00215ae}";

        static ulong LargestFree(DiskInfo d)
        {
            if (d.Layout == null || d.Size == 0) return 0;
            List<Part> ps = new List<Part>(d.Layout.Parts);
            ps.Sort(delegate (Part a, Part b) { return a.Offset.CompareTo(b.Offset); });
            ulong pos = 0, best = 0, mib = 1048576;
            foreach (Part p in ps)
            {
                if (p.Offset > pos && p.Offset - pos > best) best = p.Offset - pos;
                if (p.Offset + p.Length > pos) pos = p.Offset + p.Length;
            }
            if (d.Size > pos && d.Size - pos > best) best = d.Size - pos;
            return best > mib ? best : 0;   // gaps up to 1 MiB (alignment, GPT backup) are not free space
        }

        public static List<Dictionary<string, object>> Disks()
        {
            string bootVol = BootVolume();
            List<VolInfo> vols = VolInfos();
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (DiskInfo d in DiskInfos())
            {
                bool isBoot = false, isSystem = false;
                if (d.Layout != null)
                    foreach (Part p in d.Layout.Parts)
                    {
                        foreach (VolInfo v in vols)
                            foreach (Extent e in v.Extents)
                                if (e.Disk == d.Number && e.Offset == p.Offset && v.Path == bootVol) isBoot = true;
                        if (p.GptType == GptSystem || p.Boot) isSystem = true;
                    }
                Dictionary<string, object> m = new Dictionary<string, object>();
                m["PartitionStyle"] = DiskStyles[d.Layout == null ? 0 : d.Layout.Style];
                m["ProvisioningType"] = "Fixed";
                m["OperationalStatus"] = d.Offline ? "Offline" : "Online";
                m["HealthStatus"] = "Healthy";
                m["BusType"] = EnumName(BusTypes, d.Bus, "Unknown");
                m["UniqueIdFormat"] = "Vendor Specific";
                m["OfflineReason"] = null;
                m["ObjectId"] = ObjectId("WSP_Disk", "DI", d.Path);
                m["UniqueId"] = DiskUniqueId(d);
                m["AllocatedSize"] = d.Size;
                m["BootFromDisk"] = isBoot;
                m["FirmwareVersion"] = NullIfEmpty(Trim(d.Revision));
                m["FriendlyName"] = FriendlyName(d);
                m["Guid"] = d.Layout == null ? null : d.Layout.Guid;
                m["IsBoot"] = isBoot; m["IsClustered"] = false; m["IsHighlyAvailable"] = false; m["IsOffline"] = d.Offline;
                m["IsReadOnly"] = d.ReadOnly; m["IsScaleOut"] = false; m["IsSystem"] = isSystem || isBoot;
                m["LargestFreeExtent"] = LargestFree(d);
                m["Location"] = d.Location;
                m["LogicalSectorSize"] = d.LogicalSector;
                m["Manufacturer"] = NullIfEmpty(d.Vendor); m["Model"] = NullIfEmpty(d.Product);
                m["Number"] = d.Number;
                m["NumberOfPartitions"] = (uint)(d.Layout == null ? 0 : d.Layout.Parts.Count);
                m["Path"] = d.Path;
                m["PhysicalSectorSize"] = d.PhysicalSector;
                m["SerialNumber"] = NullIfEmpty(Trim(d.Serial));
                m["Signature"] = d.Layout != null && d.Layout.Style == 1 ? (object)d.Layout.Signature : null;
                m["Size"] = d.Size;
                res.Add(m);
            }
            return res;
        }

        static string PartitionType(Part p)
        {
            if (p.GptType != null)
            {
                switch (p.GptType)
                {
                    case GptSystem: return "System";
                    case GptReserved: return "Reserved";
                    case "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}": return "Basic";
                    case "{5808c8aa-7e8f-42e0-85d2-e1e90434cfb3}": return "LDM Metadata";
                    case "{af9b60a0-1431-4f62-bc68-3311714a69ad}": return "LDM Data";
                    case "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}": return "Recovery";
                    case "{e75caf8f-f680-4cee-afa3-b001e56efc2d}": return "Space Protective";
                    case "{eeff8352-dd2a-44db-ae83-bee1cf7481dc}": return "S2D Cache";
                    case "{03aaa829-ebfc-4e7e-aac9-c4d76c63b24b}": return "S2D Cache Metadata";
                    default: return "Unknown";
                }
            }
            switch (p.MbrType)
            {
                case 1: return "FAT12";
                case 2: case 3: return "Xenix";
                case 4: return "FAT16";
                case 5: return "Extended";
                case 6: return "Logical";
                case 7: return "IFS";
                case 10: return "OS/2 BootMgr";
                case 11: return "FAT32";
                case 12: return "FAT32 XINT13";
                case 14: return "XINT13";
                case 15: return "XINT13 Extended";
                case 65: return "PReP";
                case 66: return "LDM";
                case 99: return "Unix";
                case 231: return "Space Protective";
                default: return "Unknown";
            }
        }

        static string PartitionKey(ulong offset)
        {
            byte[] b = new byte[6]; Array.Copy(BitConverter.GetBytes(offset >> 16), b, 6);
            StringBuilder sb = new StringBuilder("{00000000-0000-0000-0000-");
            foreach (byte x in b) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
            return sb.Append('}').ToString();
        }

        public static List<Dictionary<string, object>> Partitions()
        {
            string bootVol = BootVolume();
            List<VolInfo> vols = VolInfos();
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (DiskInfo d in DiskInfos())
            {
                if (d.Layout == null) continue;
                string uid = DiskUniqueId(d);
                List<Part> parts = new List<Part>(d.Layout.Parts);
                parts.Sort(delegate (Part a, Part b) { return a.Number.CompareTo(b.Number); });
                foreach (Part p in parts)
                {
                    List<string> access = new List<string>(); char letter = '\0'; bool isBoot = false;
                    foreach (VolInfo v in vols)
                        foreach (Extent e in v.Extents)
                            if (e.Disk == d.Number && e.Offset == p.Offset)
                            {
                                foreach (string mp in v.MountPoints) access.Add(mp);
                                access.Add(v.Path);
                                if (v.Letter != '\0' && letter == '\0') letter = v.Letter;
                                if (v.Path == bootVol) isBoot = true;
                            }
                    string type = PartitionType(p);
                    bool gpt = p.GptType != null;
                    bool typeSys = gpt && (p.GptType == GptSystem || p.GptType == GptReserved);
                    bool hidden = gpt ? (typeSys || type == "Recovery" || (p.Attr & (1UL << 62)) != 0)
                                      : (p.MbrType == 0x11 || p.MbrType == 0x14 || p.MbrType == 0x16 || p.MbrType == 0x17 || p.MbrType == 0x1b || p.MbrType == 0x1c || p.MbrType == 0x1e || p.MbrType == 0x27);
                    Dictionary<string, object> m = new Dictionary<string, object>();
                    m["OperationalStatus"] = "Online";
                    m["Type"] = type;
                    m["DiskPath"] = d.Path;
                    m["ObjectId"] = ObjectId("WSP_Partition", "PR", PartitionKey(p.Offset) + d.Path);
                    m["UniqueId"] = PartitionKey(p.Offset) + uid;
                    m["AccessPaths"] = access.Count == 0 ? null : access.ToArray();
                    m["DiskId"] = d.Path;
                    m["DiskNumber"] = d.Number;
                    m["DriveLetter"] = letter;   // [char]0 when the partition has none, like Windows
                    m["GptType"] = p.GptType;
                    m["Guid"] = p.Guid;
                    m["IsActive"] = p.Boot;
                    m["IsBoot"] = isBoot;
                    m["IsDAX"] = typeSys ? null : (object)false;
                    m["IsHidden"] = hidden;
                    m["IsOffline"] = false;
                    m["IsReadOnly"] = typeSys ? null : (object)(gpt && (p.Attr & (1UL << 60)) != 0);
                    m["IsShadowCopy"] = typeSys ? null : (object)false;
                    m["IsSystem"] = gpt ? p.GptType == GptSystem : p.Boot;
                    m["MbrType"] = gpt ? null : (object)(ushort)p.MbrType;
                    m["NoDefaultDriveLetter"] = typeSys ? null : (object)(gpt && (p.Attr & (1UL << 63)) != 0);
                    m["Offset"] = p.Offset;
                    m["PartitionNumber"] = p.Number;
                    m["Size"] = p.Length;
                    m["TransitionState"] = (ushort)1;
                    res.Add(m);
                }
            }
            return res;
        }

        public static List<Dictionary<string, object>> PhysicalDisks()
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            foreach (DiskInfo d in DiskInfos())
            {
                string uid = DiskUniqueId(d);
                Dictionary<string, object> m = new Dictionary<string, object>();
                m["ClassName"] = "MSFT_PhysicalDisk";
                m["Usage"] = "Auto-Select";
                m["OperationalStatus"] = "OK";
                m["UniqueIdFormat"] = "Vendor Specific";
                m["HealthStatus"] = "Healthy";
                m["BusType"] = EnumName(BusTypes, d.Bus, "Unknown");
                m["CannotPoolReason"] = "Insufficient Capacity";
                m["SupportedUsages"] = new object[] { "Auto-Select", "Manual-Select", "Hot Spare", "Retired", "Journal" };
                m["MediaType"] = !d.SeekKnown ? "Unspecified" : d.Seek ? "HDD" : "SSD";
                m["SpindleSpeed"] = (uint)0;
                m["ObjectId"] = ObjectId("SPACES_PhysicalDisk", "PD", "{" + HashGuid(MachineId() + uid + d.Number).ToString("D").ToLowerInvariant() + "}");
                m["UniqueId"] = uid;
                m["FriendlyName"] = FriendlyName(d);
                m["Manufacturer"] = NullIfEmpty(Trim(d.Vendor));
                m["Model"] = NullIfEmpty(Trim(d.Product));
                m["PhysicalLocation"] = d.Location;
                m["SerialNumber"] = NullIfEmpty(Trim(d.Serial));
                m["AllocatedSize"] = d.Size;
                m["CanPool"] = false;
                m["DeviceId"] = d.Number.ToString(CultureInfo.InvariantCulture);
                m["FirmwareVersion"] = NullIfEmpty(Trim(d.Revision));
                m["IsPartial"] = true;
                m["LogicalSectorSize"] = (ulong)d.LogicalSector;
                m["PhysicalSectorSize"] = (ulong)d.PhysicalSector;
                m["Size"] = d.Size;
                m["VirtualDiskFootprint"] = (ulong)0;
                res.Add(m);
            }
            return res;
        }

        // The default-view size text: 1024-based, two decimals, units B..PB (beyond PB the unit is empty, as on Windows).
        public static string FormatSize(ulong bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
            double size = bytes; int i = 0;
            for (; size >= 1024 && i < units.Length; i++) size /= 1024;
            return Math.Round(size, 2, MidpointRounding.ToEven).ToString(CultureInfo.InvariantCulture) + " " + (i < units.Length ? units[i] : "");
        }
    }
}
