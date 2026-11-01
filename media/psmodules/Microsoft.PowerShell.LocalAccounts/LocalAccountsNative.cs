// Clean-room helper for the Microsoft.PowerShell.LocalAccounts script module of ReactOS-Nitro.
// Object model (type and property names) follows the Windows module's public surface; the
// implementation is original and talks to netapi32 / advapi32 only.
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace Microsoft.PowerShell.Commands
{
    public enum PrincipalSource
    {
        Unknown = 0,
        Local = 1,
        ActiveDirectory = 2,
        AzureAD = 3,
        MicrosoftAccount = 4
    }

    public class LocalPrincipal
    {
        public string Name { get; set; }
        public SecurityIdentifier SID { get; set; }
        public PrincipalSource? PrincipalSource { get; set; }
        public string ObjectClass { get; set; }

        public LocalPrincipal() { }
        public LocalPrincipal(string name) { Name = name; }
        public override string ToString() { return Name; }
    }

    public class LocalUser : LocalPrincipal
    {
        public DateTime? AccountExpires { get; set; }
        public string Description { get; set; }
        public bool Enabled { get; set; }
        public string FullName { get; set; }
        public DateTime? PasswordChangeableDate { get; set; }
        public DateTime? PasswordExpires { get; set; }
        public bool UserMayChangePassword { get; set; }
        public bool PasswordRequired { get; set; }
        public DateTime? PasswordLastSet { get; set; }
        public DateTime? LastLogon { get; set; }

        public LocalUser() { ObjectClass = "User"; }
        public LocalUser(string name) : base(name) { ObjectClass = "User"; }
        public LocalUser Clone() { return (LocalUser)MemberwiseClone(); }
    }

    public class LocalGroup : LocalPrincipal
    {
        public string Description { get; set; }

        public LocalGroup() { ObjectClass = "Group"; }
        public LocalGroup(string name) : base(name) { ObjectClass = "Group"; }
        public LocalGroup Clone() { return (LocalGroup)MemberwiseClone(); }
    }

    // ---- errors; ErrorName + Category feed the ErrorRecord the cmdlet functions write ----
    public class LocalAccountsException : Exception
    {
        public string ErrorName { get; private set; }
        public string Category { get; private set; }
        public LocalAccountsException(string errorName, string category, string message) : base(message)
        {
            ErrorName = errorName;
            Category = category;
        }
    }
    public class UserNotFoundException : LocalAccountsException
    {
        public UserNotFoundException(string target) : base("UserNotFound", "ObjectNotFound", "User " + target + " was not found.") { }
    }
    public class GroupNotFoundException : LocalAccountsException
    {
        public GroupNotFoundException(string target) : base("GroupNotFound", "ObjectNotFound", "Group " + target + " was not found.") { }
    }
    public class PrincipalNotFoundException : LocalAccountsException
    {
        public PrincipalNotFoundException(string target) : base("PrincipalNotFound", "ObjectNotFound", "Principal " + target + " was not found.") { }
    }
    public class UserExistsException : LocalAccountsException
    {
        public UserExistsException(string target) : base("UserExists", "ResourceExists", "The user " + target + " already exists.") { }
    }
    public class GroupExistsException : LocalAccountsException
    {
        public GroupExistsException(string target) : base("GroupExists", "ResourceExists", "The group " + target + " already exists.") { }
    }
    public class NameInUseException : LocalAccountsException
    {
        public NameInUseException(string target) : base("NameInUse", "ResourceExists", "The name " + target + " is already in use.") { }
    }
    public class MemberExistsException : LocalAccountsException
    {
        public MemberExistsException(string member, string group) : base("MemberExists", "ResourceExists", member + " is already a member of the group " + group + ".") { }
    }
    public class MemberNotFoundException : LocalAccountsException
    {
        public MemberNotFoundException(string member, string group) : base("MemberNotFound", "ObjectNotFound", member + " is not a member of the group " + group + ".") { }
    }
    public class InvalidNameException : LocalAccountsException
    {
        public InvalidNameException(string target) : base("InvalidName", "InvalidArgument", "The name " + target + " is not valid for a local account.") { }
    }
    public class InvalidPasswordException : LocalAccountsException
    {
        public InvalidPasswordException() : base("InvalidPassword", "InvalidArgument", "The password does not meet the password policy requirements.") { }
    }
    public class AccessDeniedException : LocalAccountsException
    {
        public AccessDeniedException(string target) : base("AccessDenied", "PermissionDenied", "Access was denied while operating on " + target + ".") { }
    }
    public class LocalAccountsInternalException : LocalAccountsException
    {
        public int Code { get; private set; }
        public LocalAccountsInternalException(int code, string target) : base("Internal", "InvalidOperation", "Local account operation on " + target + " failed with error " + code + ".") { Code = code; }
        public LocalAccountsInternalException(string message) : base("Internal", "InvalidOperation", message) { }
    }


    // Name stand-ins: the ErrorRecords written by the script cmdlets are stamped as coming from these types, so
    // FullyQualifiedErrorId reads "<ErrorName>,Microsoft.PowerShell.Commands.<Verb><Noun>Command" like the Windows cmdlets.
    // They are never registered as commands.
    [Cmdlet("Add", "LocalGroupMember")] public class AddLocalGroupMemberCommand : PSCmdlet { }
    [Cmdlet("Disable", "LocalUser")] public class DisableLocalUserCommand : PSCmdlet { }
    [Cmdlet("Enable", "LocalUser")] public class EnableLocalUserCommand : PSCmdlet { }
    [Cmdlet("Get", "LocalGroup")] public class GetLocalGroupCommand : PSCmdlet { }
    [Cmdlet("Get", "LocalGroupMember")] public class GetLocalGroupMemberCommand : PSCmdlet { }
    [Cmdlet("Get", "LocalUser")] public class GetLocalUserCommand : PSCmdlet { }
    [Cmdlet("New", "LocalGroup")] public class NewLocalGroupCommand : PSCmdlet { }
    [Cmdlet("New", "LocalUser")] public class NewLocalUserCommand : PSCmdlet { }
    [Cmdlet("Remove", "LocalGroup")] public class RemoveLocalGroupCommand : PSCmdlet { }
    [Cmdlet("Remove", "LocalGroupMember")] public class RemoveLocalGroupMemberCommand : PSCmdlet { }
    [Cmdlet("Remove", "LocalUser")] public class RemoveLocalUserCommand : PSCmdlet { }
    [Cmdlet("Rename", "LocalGroup")] public class RenameLocalGroupCommand : PSCmdlet { }
    [Cmdlet("Rename", "LocalUser")] public class RenameLocalUserCommand : PSCmdlet { }
    [Cmdlet("Set", "LocalGroup")] public class SetLocalGroupCommand : PSCmdlet { }
    [Cmdlet("Set", "LocalUser")] public class SetLocalUserCommand : PSCmdlet { }

    public static class ErrorStamp
    {
        // Returns an ErrorRecord for the exception whose InvocationInfo names the Windows cmdlet type. Falls back to a
        // plain record (FullyQualifiedErrorId ends in the function name) if the engine internals are not as expected.
        public static ErrorRecord Create(LocalAccountsException e, object target, string commandName, IScriptExtent position)
        {
            ErrorCategory cat = (ErrorCategory)Enum.Parse(typeof(ErrorCategory), e.Category);
            ErrorRecord rec = new ErrorRecord(e, e.ErrorName, cat, target);
            try
            {
                Type t = typeof(ErrorStamp).Assembly.GetType("Microsoft.PowerShell.Commands." + commandName.Replace("-", "") + "Command");
                if (t == null) return rec;
                CmdletInfo info = new CmdletInfo(commandName, t);
                InvocationInfo inv = InvocationInfo.Create(info, position);
                BindingFlags f = BindingFlags.NonPublic | BindingFlags.Instance;
                typeof(ErrorRecord).GetMethod("SetInvocationInfo", f).Invoke(rec, new object[] { inv });
                typeof(ErrorRecord).GetProperty("PreserveInvocationInfoOnce", f).SetValue(rec, true, null);
            }
            catch (Exception) { }
            return rec;
        }
    }


    // Result of a helper call. The script cmdlets call LocalAccountsNative through Op.Call so that a failure comes back
    // as a value: an exception thrown through the script engine would be logged in $Error and in the caller's
    // -ErrorVariable before the cmdlet gets to write its own ErrorRecord.
    public sealed class OpResult
    {
        public object Value;
        public LocalAccountsException Error;
    }

    public static class Op
    {
        public static OpResult Ok(object value) { OpResult r = new OpResult(); r.Value = value; return r; }
        public static OpResult Fail(LocalAccountsException e) { OpResult r = new OpResult(); r.Error = e; return r; }

        public static OpResult Call(string method, params object[] args)
        {
            try
            {
                MethodInfo m = typeof(LocalAccountsNative).GetMethod(method, BindingFlags.Public | BindingFlags.Static);
                if (m == null) return Fail(new LocalAccountsInternalException("Unknown helper " + method));
                object[] a = args ?? new object[0];
                for (int i = 0; i < a.Length; i++)
                {
                    PSObject po = a[i] as PSObject;
                    if (po != null) a[i] = po.BaseObject;
                }
                return Ok(m.Invoke(null, a));
            }
            catch (TargetInvocationException t)
            {
                LocalAccountsException e = t.InnerException as LocalAccountsException;
                return Fail(e ?? new LocalAccountsInternalException(t.InnerException != null ? t.InnerException.Message : t.Message));
            }
            catch (Exception x)
            {
                return Fail(new LocalAccountsInternalException(x.Message));
            }
        }
    }

    // A resolved principal used by the group member cmdlets.
    public class ResolvedPrincipal
    {
        public SecurityIdentifier SID;
        public string FullName;     // DOMAIN\name as the system reports it
        public int Use;             // SID_NAME_USE
    }

    public static class LocalAccountsNative
    {
        const int ERROR_ACCESS_DENIED = 5;
        const int ERROR_INVALID_NAME = 123;
        const int ERROR_MORE_DATA = 234;
        const int ERROR_NO_SUCH_ALIAS = 1376;
        const int ERROR_MEMBER_NOT_IN_ALIAS = 1377;
        const int ERROR_MEMBER_IN_ALIAS = 1378;
        const int ERROR_ALIAS_EXISTS = 1379;
        const int ERROR_NO_SUCH_MEMBER = 1387;
        const int ERROR_INVALID_MEMBER = 1388;
        const int NERR_BadUsername = 2202;
        const int NERR_GroupNotFound = 2220;
        const int NERR_UserNotFound = 2221;
        const int NERR_GroupExists = 2223;
        const int NERR_UserExists = 2224;
        const int NERR_PasswordTooShort = 2245;
        const int NERR_BadPassword = 2203;
        const int NERR_InvalidComputer = 2351;
        const int NERR_SpeGroupOp = 2234;

        public const int UF_ACCOUNTDISABLE = 0x2;
        public const int UF_PASSWD_NOTREQD = 0x20;
        public const int UF_PASSWD_CANT_CHANGE = 0x40;
        public const int UF_NORMAL_ACCOUNT = 0x200;
        public const int UF_DONT_EXPIRE_PASSWD = 0x10000;
        const uint TIMEQ_FOREVER = 0xFFFFFFFF;

        // ---------------------------------------------------------------- P/Invoke
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserEnum(string server, int level, int filter, out IntPtr buf, int prefMax, out int read, out int total, ref int resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserGetInfo(string server, string name, int level, out IntPtr buf);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserAdd(string server, int level, IntPtr buf, out int parmErr);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserDel(string server, string name);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserSetInfo(string server, string name, int level, IntPtr buf, out int parmErr);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserModalsGet(string server, int level, out IntPtr buf);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupEnum(string server, int level, out IntPtr buf, int prefMax, out int read, out int total, ref IntPtr resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupGetInfo(string server, string name, int level, out IntPtr buf);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupAdd(string server, int level, IntPtr buf, out int parmErr);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupDel(string server, string name);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupSetInfo(string server, string name, int level, IntPtr buf, out int parmErr);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupGetMembers(string server, string name, int level, out IntPtr buf, int prefMax, out int read, out int total, ref IntPtr resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupAddMembers(string server, string name, int level, IntPtr buf, int count);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupDelMembers(string server, string name, int level, IntPtr buf, int count);
        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buf);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupAccountNameW(string system, string name, byte[] sid, ref int cbSid, StringBuilder domain, ref int cchDomain, out int use);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupAccountSidW(string system, byte[] sid, StringBuilder name, ref int cchName, StringBuilder domain, ref int cchDomain, out int use);

        // USER_INFO_4 as returned by NetUserEnum/NetUserGetInfo (level 4)
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct USER_INFO_4
        {
            public IntPtr name;
            public IntPtr password;
            public uint password_age;
            public uint priv;
            public IntPtr home_dir;
            public IntPtr comment;
            public uint flags;
            public IntPtr script_path;
            public uint auth_flags;
            public IntPtr full_name;
            public IntPtr usr_comment;
            public IntPtr parms;
            public IntPtr workstations;
            public uint last_logon;
            public uint last_logoff;
            public uint acct_expires;
            public uint max_storage;
            public uint units_per_week;
            public IntPtr logon_hours;
            public uint bad_pw_count;
            public uint num_logons;
            public IntPtr logon_server;
            public uint country_code;
            public uint code_page;
            public IntPtr user_sid;
            public uint primary_group_id;
            public IntPtr profile;
            public IntPtr home_dir_drive;
            public uint password_expired;
        }

        // USER_INFO_1 for NetUserAdd
        [StructLayout(LayoutKind.Sequential)]
        struct USER_INFO_1
        {
            public IntPtr name;
            public IntPtr password;
            public uint password_age;
            public uint priv;
            public IntPtr home_dir;
            public IntPtr comment;
            public uint flags;
            public IntPtr script_path;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct USER_MODALS_INFO_0
        {
            public uint min_passwd_len;
            public uint max_passwd_age;
            public uint min_passwd_age;
            public uint force_logoff;
            public uint password_hist_len;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LOCALGROUP_INFO_1
        {
            public IntPtr name;
            public IntPtr comment;
        }

        // ---------------------------------------------------------------- helpers
        static string Str(IntPtr p) { return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p); }

        static Exception Map(int rc, string target, string group)
        {
            switch (rc)
            {
                case NERR_UserNotFound: return new UserNotFoundException(target);
                case NERR_GroupNotFound:
                case ERROR_NO_SUCH_ALIAS: return new GroupNotFoundException(target);
                case NERR_UserExists: return new UserExistsException(target);
                case NERR_GroupExists:
                case ERROR_ALIAS_EXISTS: return new GroupExistsException(target);
                case ERROR_MEMBER_IN_ALIAS: return new MemberExistsException(target, group);
                case ERROR_MEMBER_NOT_IN_ALIAS: return new MemberNotFoundException(target, group);
                case ERROR_NO_SUCH_MEMBER:
                case ERROR_INVALID_MEMBER: return new PrincipalNotFoundException(target);
                case ERROR_INVALID_NAME:
                case NERR_BadUsername: return new InvalidNameException(target);
                case NERR_PasswordTooShort:
                case NERR_BadPassword: return new InvalidPasswordException();
                case ERROR_ACCESS_DENIED: return new AccessDeniedException(target);
                default: return new LocalAccountsInternalException(rc, target);
            }
        }

        static readonly char[] BadNameChars = "\"/\\[]:|<>+=;,?*".ToCharArray();

        // account and group names: the characters SAM refuses, control characters, empty or trailing-period names
        static void ValidateName(string name)
        {
            bool bad = string.IsNullOrWhiteSpace(name) || name.IndexOfAny(BadNameChars) >= 0 || name.EndsWith(".");
            if (!bad) foreach (char c in name) { if (c < ' ') { bad = true; break; } }
            if (bad) throw new InvalidNameException(name);
        }

        static void Check(int rc, string target) { if (rc != 0) throw Map(rc, target, null); }

        static DateTime? FromUnix(uint secs)
        {
            if (secs == 0 || secs == TIMEQ_FOREVER) return null;
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(secs).ToLocalTime();
        }

        static uint ToUnix(DateTime d)
        {
            DateTime u = d.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(d, DateTimeKind.Local).ToUniversalTime() : d.ToUniversalTime();
            double s = (u - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            if (s < 1) s = 1;
            if (s > 0xFFFFFFFE) s = 0xFFFFFFFE;
            return (uint)s;
        }

        static string _computer;
        public static string ComputerName
        {
            get { if (_computer == null) _computer = Environment.MachineName; return _computer; }
        }

        // ---------------------------------------------------------------- SID <-> name
        public static ResolvedPrincipal LookupName(string name)
        {
            int cbSid = 0, cchDom = 0, use;
            LookupAccountNameW(null, name, null, ref cbSid, null, ref cchDom, out use);
            if (cbSid == 0) return null;
            byte[] sid = new byte[cbSid];
            StringBuilder dom = new StringBuilder(cchDom + 1);
            if (!LookupAccountNameW(null, name, sid, ref cbSid, dom, ref cchDom, out use)) return null;
            SecurityIdentifier s = new SecurityIdentifier(sid, 0);
            ResolvedPrincipal r = LookupSid(s);
            if (r != null) return r;
            ResolvedPrincipal r2 = new ResolvedPrincipal();
            r2.SID = s; r2.FullName = (dom.Length > 0 ? dom + "\\" : "") + name; r2.Use = use;
            return r2;
        }

        public static ResolvedPrincipal LookupSid(SecurityIdentifier sid)
        {
            byte[] b = new byte[sid.BinaryLength];
            sid.GetBinaryForm(b, 0);
            int cchName = 0, cchDom = 0, use;
            LookupAccountSidW(null, b, null, ref cchName, null, ref cchDom, out use);
            if (cchName == 0) return null;
            StringBuilder n = new StringBuilder(cchName + 1), d = new StringBuilder(cchDom + 1);
            if (!LookupAccountSidW(null, b, n, ref cchName, d, ref cchDom, out use)) return null;
            ResolvedPrincipal r = new ResolvedPrincipal();
            r.SID = sid; r.Use = use;
            r.FullName = d.Length > 0 ? d + "\\" + n : n.ToString();
            return r;
        }

        static string DomainOf(string full) { int i = full.LastIndexOf('\\'); return i < 0 ? "" : full.Substring(0, i); }
        public static string ShortName(string full) { int i = full.LastIndexOf('\\'); return i < 0 ? full : full.Substring(i + 1); }

        static PrincipalSource SourceOf(string full)
        {
            string d = DomainOf(full);
            if (string.Equals(d, ComputerName, StringComparison.OrdinalIgnoreCase)) return PrincipalSource.Local;
            if (d.Length == 0) return PrincipalSource.Unknown;
            if (d.StartsWith("AzureAD", StringComparison.OrdinalIgnoreCase)) return PrincipalSource.AzureAD;
            if (d.StartsWith("MicrosoftAccount", StringComparison.OrdinalIgnoreCase)) return PrincipalSource.MicrosoftAccount;
            if (d.StartsWith("NT ", StringComparison.OrdinalIgnoreCase) || d.Equals("BUILTIN", StringComparison.OrdinalIgnoreCase)
                || d.Equals("Window Manager", StringComparison.OrdinalIgnoreCase) || d.Equals("Font Driver Host", StringComparison.OrdinalIgnoreCase))
                return PrincipalSource.Unknown;
            return PrincipalSource.ActiveDirectory;
        }

        static string ClassOf(int use)
        {
            // SidTypeUser = 1, Group = 2, Domain = 3, Alias = 4, WellKnownGroup = 5
            switch (use)
            {
                case 1: return "User";
                case 2: case 4: case 5: return "Group";
                case 6: return "Unknown";
                default: return "Unknown";
            }
        }

        // ---------------------------------------------------------------- users
        static LocalUser UserFromInfo(USER_INFO_4 u, uint maxAge, uint minAge)
        {
            LocalUser r = new LocalUser();
            r.Name = Str(u.name);
            r.Description = Str(u.comment) ?? "";
            r.FullName = Str(u.full_name) ?? "";
            r.Enabled = (u.flags & UF_ACCOUNTDISABLE) == 0;
            r.PasswordRequired = (u.flags & UF_PASSWD_NOTREQD) == 0;
            r.UserMayChangePassword = (u.flags & UF_PASSWD_CANT_CHANGE) == 0;
            r.AccountExpires = FromUnix(u.acct_expires);
            r.LastLogon = FromUnix(u.last_logon);
            if (u.user_sid != IntPtr.Zero) r.SID = new SecurityIdentifier(u.user_sid);
            r.PrincipalSource = PrincipalSource.Local;
            // password_age is seconds since the password was set; a never-set password reports an age that
            // reaches back before the Unix epoch (or 0)
            double nowUnix = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            if (u.password_age > 0 && u.password_age < nowUnix - 86400.0 * 366)
            {
                r.PasswordLastSet = DateTime.Now.AddSeconds(-(double)u.password_age);
                r.PasswordChangeableDate = minAge == TIMEQ_FOREVER ? (DateTime?)null : r.PasswordLastSet.Value.AddSeconds(minAge);
                if ((u.flags & UF_DONT_EXPIRE_PASSWD) == 0 && maxAge != TIMEQ_FOREVER && maxAge != 0)
                    r.PasswordExpires = r.PasswordLastSet.Value.AddSeconds(maxAge);
            }
            return r;
        }

        static void GetModals(out uint maxAge, out uint minAge)
        {
            maxAge = TIMEQ_FOREVER; minAge = 0;
            IntPtr buf;
            if (NetUserModalsGet(null, 0, out buf) == 0 && buf != IntPtr.Zero)
            {
                USER_MODALS_INFO_0 m = (USER_MODALS_INFO_0)Marshal.PtrToStructure(buf, typeof(USER_MODALS_INFO_0));
                maxAge = m.max_passwd_age; minAge = m.min_passwd_age;
                NetApiBufferFree(buf);
            }
        }

        public static LocalUser[] GetUsers()
        {
            uint maxAge, minAge;
            GetModals(out maxAge, out minAge);
            List<LocalUser> list = new List<LocalUser>();
            int resume = 0;
            int sz = Marshal.SizeOf(typeof(USER_INFO_4));
            while (true)
            {
                IntPtr buf; int read, total;
                int rc = NetUserEnum(null, 4, 0, out buf, -1, out read, out total, ref resume);
                if (rc != 0 && rc != ERROR_MORE_DATA) throw Map(rc, "users", null);
                try
                {
                    for (int i = 0; i < read; i++)
                    {
                        USER_INFO_4 u = (USER_INFO_4)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + (long)i * sz), typeof(USER_INFO_4));
                        list.Add(UserFromInfo(u, maxAge, minAge));
                    }
                }
                finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
                if (rc == 0) break;
                if (read == 0 && resume == 0) break;
            }
            return list.ToArray();
        }

        public static LocalUser GetUser(string name)
        {
            uint maxAge, minAge;
            GetModals(out maxAge, out minAge);
            IntPtr buf;
            int rc = NetUserGetInfo(null, name, 4, out buf);
            if (rc != 0) throw Map(rc, name, null);
            try { return UserFromInfo((USER_INFO_4)Marshal.PtrToStructure(buf, typeof(USER_INFO_4)), maxAge, minAge); }
            finally { NetApiBufferFree(buf); }
        }

        static int GetUserFlags(string name)
        {
            IntPtr buf;
            int rc = NetUserGetInfo(null, name, 1, out buf);
            if (rc != 0) throw Map(rc, name, null);
            try { return (int)((USER_INFO_1)Marshal.PtrToStructure(buf, typeof(USER_INFO_1))).flags; }
            finally { NetApiBufferFree(buf); }
        }

        // flags: the complete UF_* value to create the account with
        public static void AddUser(string name, SecureString password, string description, int flags)
        {
            ValidateName(name);
            IntPtr pName = Marshal.StringToHGlobalUni(name);
            IntPtr pComment = description == null ? IntPtr.Zero : Marshal.StringToHGlobalUni(description);
            IntPtr pPass = password != null ? Marshal.SecureStringToGlobalAllocUnicode(password) : Marshal.StringToHGlobalUni("");
            IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(USER_INFO_1)));
            try
            {
                USER_INFO_1 u = new USER_INFO_1();
                u.name = pName; u.password = pPass; u.priv = 1; u.comment = pComment; u.flags = (uint)flags;
                Marshal.StructureToPtr(u, buf, false);
                int parm;
                Check(NetUserAdd(null, 1, buf, out parm), name);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
                Marshal.FreeHGlobal(pName);
                if (pComment != IntPtr.Zero) Marshal.FreeHGlobal(pComment);
                Marshal.ZeroFreeGlobalAllocUnicode(pPass);
            }
        }

        public static void RemoveUser(string name) { Check(NetUserDel(null, name), name); }

        static void SetUserPtr(string name, int level, IntPtr value)
        {
            IntPtr buf = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                Marshal.WriteIntPtr(buf, value);
                int parm;
                Check(NetUserSetInfo(null, name, level, buf, out parm), name);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static void SetUserString(string name, int level, string value)
        {
            IntPtr p = Marshal.StringToHGlobalUni(value ?? "");
            try { SetUserPtr(name, level, p); } finally { Marshal.FreeHGlobal(p); }
        }

        static void SetUserDword(string name, int level, uint value)
        {
            IntPtr buf = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteInt32(buf, unchecked((int)value));
                int parm;
                Check(NetUserSetInfo(null, name, level, buf, out parm), name);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static void SetUserDescription(string name, string v) { SetUserString(name, 1007, v); }
        public static void SetUserFullName(string name, string v) { SetUserString(name, 1011, v); }
        public static void SetUserAccountExpires(string name, DateTime? v) { SetUserDword(name, 1017, v.HasValue ? ToUnix(v.Value) : TIMEQ_FOREVER); }

        public static void SetUserPassword(string name, SecureString password)
        {
            IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(password);
            try { SetUserPtr(name, 1003, p); } finally { Marshal.ZeroFreeGlobalAllocUnicode(p); }
        }

        // sets or clears one UF_* bit of the account flags
        public static void SetUserFlag(string name, int mask, bool on)
        {
            int f = GetUserFlags(name);
            int n = on ? (f | mask) : (f & ~mask);
            if (n != f) SetUserDword(name, 1008, (uint)n);
        }

        public static void RenameUser(string name, string newName)
        {
            ValidateName(newName);
            SetUserString(name, 0, newName);
        }

        // ---------------------------------------------------------------- groups
        public static LocalGroup[] GetGroups()
        {
            List<LocalGroup> list = new List<LocalGroup>();
            IntPtr resume = IntPtr.Zero;
            int sz = Marshal.SizeOf(typeof(LOCALGROUP_INFO_1));
            while (true)
            {
                IntPtr buf; int read, total;
                int rc = NetLocalGroupEnum(null, 1, out buf, -1, out read, out total, ref resume);
                if (rc != 0 && rc != ERROR_MORE_DATA) throw Map(rc, "groups", null);
                try
                {
                    for (int i = 0; i < read; i++)
                    {
                        LOCALGROUP_INFO_1 g = (LOCALGROUP_INFO_1)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + (long)i * sz), typeof(LOCALGROUP_INFO_1));
                        list.Add(MakeGroup(Str(g.name), Str(g.comment)));
                    }
                }
                finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
                if (rc == 0) break;
                if (read == 0) break;
            }
            return list.ToArray();
        }

        static LocalGroup MakeGroup(string name, string comment)
        {
            LocalGroup g = new LocalGroup();
            g.Name = name;
            g.Description = comment ?? "";
            g.PrincipalSource = PrincipalSource.Local;
            ResolvedPrincipal r = LookupName(name);
            if (r != null) g.SID = r.SID;
            return g;
        }

        public static LocalGroup GetGroup(string name)
        {
            IntPtr buf;
            int rc = NetLocalGroupGetInfo(null, name, 1, out buf);
            if (rc != 0) throw Map(rc, name, null);
            try
            {
                LOCALGROUP_INFO_1 g = (LOCALGROUP_INFO_1)Marshal.PtrToStructure(buf, typeof(LOCALGROUP_INFO_1));
                return MakeGroup(Str(g.name) ?? name, Str(g.comment));
            }
            finally { NetApiBufferFree(buf); }
        }

        public static void AddGroup(string name, string description)
        {
            ValidateName(name);
            IntPtr pName = Marshal.StringToHGlobalUni(name);
            IntPtr pComment = description == null ? IntPtr.Zero : Marshal.StringToHGlobalUni(description);
            IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LOCALGROUP_INFO_1)));
            try
            {
                LOCALGROUP_INFO_1 g = new LOCALGROUP_INFO_1();
                g.name = pName; g.comment = pComment;
                Marshal.StructureToPtr(g, buf, false);
                int parm;
                Check(NetLocalGroupAdd(null, 1, buf, out parm), name);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
                Marshal.FreeHGlobal(pName);
                if (pComment != IntPtr.Zero) Marshal.FreeHGlobal(pComment);
            }
        }

        public static void RemoveGroup(string name) { Check(NetLocalGroupDel(null, name), name); }

        static void SetGroupString(string name, int level, string value)
        {
            IntPtr p = Marshal.StringToHGlobalUni(value ?? "");
            IntPtr buf = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                Marshal.WriteIntPtr(buf, p);
                int parm;
                Check(NetLocalGroupSetInfo(null, name, level, buf, out parm), name);
            }
            finally { Marshal.FreeHGlobal(buf); Marshal.FreeHGlobal(p); }
        }

        public static void SetGroupDescription(string name, string v) { SetGroupString(name, 1002, v); }
        public static void RenameGroup(string name, string newName) { ValidateName(newName); SetGroupString(name, 0, newName); }

        public static ResolvedPrincipal[] GetGroupMemberSids(string group)
        {
            List<ResolvedPrincipal> list = new List<ResolvedPrincipal>();
            IntPtr resume = IntPtr.Zero;
            while (true)
            {
                IntPtr buf; int read, total;
                int rc = NetLocalGroupGetMembers(null, group, 0, out buf, -1, out read, out total, ref resume);
                if (rc != 0 && rc != ERROR_MORE_DATA) throw Map(rc, group, null);
                try
                {
                    for (int i = 0; i < read; i++)
                    {
                        IntPtr ps = Marshal.ReadIntPtr(buf, i * IntPtr.Size);
                        ResolvedPrincipal r = new ResolvedPrincipal();
                        r.SID = new SecurityIdentifier(ps);
                        list.Add(r);
                    }
                }
                finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
                if (rc == 0) break;
                if (read == 0) break;
            }
            return list.ToArray();
        }

        public static LocalPrincipal[] GetGroupMembers(string group)
        {
            ResolvedPrincipal[] sids = GetGroupMemberSids(group);
            List<LocalPrincipal> list = new List<LocalPrincipal>();
            foreach (ResolvedPrincipal s in sids)
            {
                ResolvedPrincipal r = LookupSid(s.SID);
                LocalPrincipal p = new LocalPrincipal();
                p.SID = s.SID;
                if (r != null)
                {
                    p.Name = r.FullName;
                    p.ObjectClass = ClassOf(r.Use);
                    p.PrincipalSource = SourceOf(r.FullName);
                }
                else
                {
                    p.Name = s.SID.Value;
                    p.ObjectClass = "Unknown";
                    p.PrincipalSource = PrincipalSource.Unknown;
                }
                list.Add(p);
            }
            return list.ToArray();
        }

        static void MemberOp(bool add, string group, SecurityIdentifier sid, string memberDisplay)
        {
            // netapi32 on this system does not report a duplicate add or a missing remove: check the membership here
            bool present = false;
            foreach (ResolvedPrincipal m in GetGroupMemberSids(group)) { if (m.SID.Equals(sid)) { present = true; break; } }
            if (add && present) throw new MemberExistsException(memberDisplay, group);
            if (!add && !present) throw new MemberNotFoundException(memberDisplay, group);
            byte[] b = new byte[sid.BinaryLength];
            sid.GetBinaryForm(b, 0);
            IntPtr pSid = Marshal.AllocHGlobal(b.Length);
            IntPtr buf = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                Marshal.Copy(b, 0, pSid, b.Length);
                Marshal.WriteIntPtr(buf, pSid);
                int rc = add ? NetLocalGroupAddMembers(null, group, 0, buf, 1) : NetLocalGroupDelMembers(null, group, 0, buf, 1);
                if (rc != 0) throw Map(rc, memberDisplay, group);
            }
            finally { Marshal.FreeHGlobal(buf); Marshal.FreeHGlobal(pSid); }
        }

        public static void AddGroupMember(string group, SecurityIdentifier sid, string memberDisplay) { MemberOp(true, group, sid, memberDisplay); }
        public static void RemoveGroupMember(string group, SecurityIdentifier sid, string memberDisplay) { MemberOp(false, group, sid, memberDisplay); }
    }
}
