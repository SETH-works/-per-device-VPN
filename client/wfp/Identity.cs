using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Walnuts.Wfp;

static class Identity {
    public static string ConfigPath=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"WalnutsWfp","lab.json");
    [StructLayout(LayoutKind.Sequential)]struct ServiceConfig {public uint Type,Start,Error;public IntPtr Binary,Group;public uint Tag;public IntPtr Dependencies,Account,Display;}
    [StructLayout(LayoutKind.Sequential)]struct ServiceStatus {public uint Type,State,Controls,Win32Exit,ServiceExit,Checkpoint,WaitHint,Pid,Flags;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryServiceConfig(IntPtr svc,IntPtr config,uint length,out uint needed);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool QueryServiceStatusEx(IntPtr svc,int level,out ServiceStatus status,int size,out uint needed);
    [DllImport("advapi32.dll")]static extern bool CloseServiceHandle(IntPtr value);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr value);
    [DllImport("iphlpapi.dll")]static extern uint ConvertInterfaceGuidToLuid(ref Guid guid,out ulong luid);
    public static (string Path,uint Start,uint Pid) Service(string name) {
        var manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Fault(ExitCode.Identity,"Cannot query SCM");
        IntPtr svc=IntPtr.Zero,p=IntPtr.Zero;
        try {
            svc=OpenService(manager,name,5);if(svc==IntPtr.Zero)throw new Fault(ExitCode.Identity,"Required service missing: "+name);
            QueryServiceConfig(svc,IntPtr.Zero,0,out uint needed);
            if(needed==0 || needed>65536)throw new Fault(ExitCode.Identity,"Invalid SCM configuration length");
            p=Marshal.AllocHGlobal((int)needed);
            if(!QueryServiceConfig(svc,p,needed,out _))throw new Fault(ExitCode.Identity,"Cannot read service configuration");
            var cfg=Marshal.PtrToStructure<ServiceConfig>(p);
            string binary=Marshal.PtrToStringUni(cfg.Binary)??"";
            var match=Regex.Match(binary,"^\"([^\"]+\\.exe)\"(?:\\s|$)|^([^\\s\"]+\\.exe)(?:\\s|$)",RegexOptions.IgnoreCase);
            if(!match.Success)throw new Fault(ExitCode.Identity,"Ambiguous service executable");
            string path=match.Groups[1].Success?match.Groups[1].Value:match.Groups[2].Value;
            if(!Path.IsPathFullyQualified(path))throw new Fault(ExitCode.Identity,"Relative service executable");
            if(!QueryServiceStatusEx(svc,0,out var status,Marshal.SizeOf<ServiceStatus>(),out _))throw new Fault(ExitCode.Identity,"Cannot read service state");
            return (Path.GetFullPath(path),cfg.Start,status.State==4?status.Pid:0);
        } finally{if(p!=IntPtr.Zero)Marshal.FreeHGlobal(p);if(svc!=IntPtr.Zero)CloseServiceHandle(svc);CloseServiceHandle(manager);}
    }
    public static string ServiceSid(string name)=>((SecurityIdentifier)new NTAccount("NT SERVICE",name).Translate(typeof(SecurityIdentifier))).Value;
    public static void TrustedPath(string path,bool directory=false) {
        // Reject reparse points at every ancestor, and effective write ACEs for
        // principals other than SYSTEM, Administrators or TrustedInstaller.
        var trustedInstaller=ServiceSid("TrustedInstaller");
        bool leaf=true;
        for(string? current=Path.GetFullPath(path);current!=null;current=Path.GetDirectoryName(current)) {
            FileSystemInfo item=(directory || Directory.Exists(current))?new DirectoryInfo(current):new FileInfo(current);
            if((item.Attributes&FileAttributes.ReparsePoint)!=0)throw new Fault(ExitCode.Identity,"Reparse point in trusted path");
            FileSystemSecurity acl=item is DirectoryInfo d?d.GetAccessControl():((FileInfo)item).GetAccessControl();
            string owner=(acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value ?? throw new Fault(ExitCode.Identity,"Missing file owner");
            if(owner is not ("S-1-5-18" or "S-1-5-32-544") && owner!=trustedInstaller)throw new Fault(ExitCode.Identity,"Untrusted file owner: "+current);
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                if(rule.AccessControlType!=AccessControlType.Allow || (rule.PropagationFlags&PropagationFlags.InheritOnly)!=0)continue;
                string sid=rule.IdentityReference.Value;
                var writes=FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
                if(leaf)writes|=FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.WriteAttributes|FileSystemRights.WriteExtendedAttributes;
                if((rule.FileSystemRights&writes)!=0 && sid is not ("S-1-5-18" or "S-1-5-32-544") && sid!=trustedInstaller)
                    throw new Fault(ExitCode.Identity,"Untrusted write ACE: "+current);
            }
            directory=true;
            leaf=false;
        }
    }
    public static void LabMachine(Configuration c) {
        Policy.Validate(c);
        if(!Environment.MachineName.Equals(c.Hostname,StringComparison.OrdinalIgnoreCase))throw new Fault(ExitCode.Identity,"Lab hostname mismatch");
        using var bios=Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
        string product=Convert.ToString(bios?.GetValue("SystemProductName"))??"";
        if(!new[]{"Virtual Machine","VirtualBox","VMware","KVM","QEMU"}.Any(s=>product.Contains(s,StringComparison.OrdinalIgnoreCase)))
            throw new Fault(ExitCode.Unsupported,"A disposable VM identity is required; hardware hosts are refused");
    }
    public static void Installed(bool requireService=true) {
        string path=Environment.ProcessPath??throw new Fault(ExitCode.Identity,"Executable path unavailable");
        string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"WalnutsWfp")+Path.DirectorySeparatorChar;
        if(!path.StartsWith(root,StringComparison.OrdinalIgnoreCase))throw new Fault(ExitCode.Identity,"Helper must be installed in protected Program Files/WalnutsWfp");
        TrustedPath(path);TrustedPath(ConfigPath);
        if(requireService) {
            var guard=Service(Policy.ServiceName);
            if(guard.Start!=2 || !guard.Path.Equals(path,StringComparison.OrdinalIgnoreCase))throw new Fault(ExitCode.Identity,"Guard service must be automatic and use this executable");
        }
    }
    public static Manifest Resolve(Configuration c) {
        LabMachine(c);
        var ts=Service("Tailscale");
        if(ts.Pid==0)throw new Fault(ExitCode.Identity,"Tailscale service is not running");
        TrustedPath(ts.Path);
        string hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ts.Path)));
        if(!hash.Equals(c.ServiceSha256,StringComparison.OrdinalIgnoreCase))throw new Fault(ExitCode.Identity,"Pinned service executable changed");
        using var process=Process.GetProcessById((int)ts.Pid);
        if(!string.Equals(process.MainModule?.FileName,ts.Path,StringComparison.OrdinalIgnoreCase))throw new Fault(ExitCode.Identity,"Running service image differs from SCM");
        string sid=ServiceSid("Tailscale");
        if(!OpenProcessToken(process.Handle,8,out var token))throw new Fault(ExitCode.Identity,"Cannot verify service token");
        try {
            using var identity=new WindowsIdentity(token);
            if(identity.User?.Value!="S-1-5-18" || identity.Groups?.Any(g=>g.Value==sid)!=true)
                throw new Fault(ExitCode.Identity,"Tailscale token lacks the expected LocalSystem/service SID. Do not broaden the exception.");
        } finally{CloseHandle(token);}
        ulong ResolveAdapter(Guid guid,bool tunnel) {
            var adapter=NetworkInterface.GetAllNetworkInterfaces().SingleOrDefault(n=>Guid.TryParse(n.Id,out var id)&&id==guid);
            if(adapter==null || (tunnel && !adapter.Description.Contains("Tailscale",StringComparison.OrdinalIgnoreCase)) || (!tunnel && adapter.Description.Contains("Tailscale",StringComparison.OrdinalIgnoreCase)))
                throw new Fault(ExitCode.Identity,"Reviewed adapter GUID/type differs");
            Native.Check(ConvertInterfaceGuidToLuid(ref guid,out ulong luid),"Resolve adapter LUID");return luid;
        }
        return new(c,ResolveAdapter(c.TunnelAdapter,true),ResolveAdapter(c.UnderlayAdapter,false),ts.Path,sid,ServiceSid("Dhcp"),Native.AppId(ts.Path),Native.AppId(Path.Combine(Environment.SystemDirectory,"svchost.exe")));
    }
}
