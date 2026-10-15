using System.Runtime.InteropServices;

namespace Walnuts.Wfp;

// Native SCM hosting avoids a service framework/NuGet dependency. It never
// deletes filters when stopped and never changes Tailscale, DNS or routes.
static class GuardService {
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]delegate void MainDelegate(uint argc,IntPtr argv);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]delegate uint HandlerDelegate(uint control,uint eventType,IntPtr data,IntPtr context);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct Entry {[MarshalAs(UnmanagedType.LPWStr)]public string? Name;public MainDelegate? Main;}
    [StructLayout(LayoutKind.Sequential)]struct Status {public uint Type,State,Controls,Win32Exit,ServiceExit,Checkpoint,WaitHint;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool StartServiceCtrlDispatcher([In] Entry[] table);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr RegisterServiceCtrlHandlerEx(string name,HandlerDelegate handler,IntPtr context);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool SetServiceStatus(IntPtr handle,ref Status status);
    static readonly ManualResetEventSlim Stop=new(false);
    static readonly MainDelegate Main=ServiceMain;
    static readonly HandlerDelegate Handler=Control;
    static IntPtr statusHandle;
    static uint Control(uint control,uint _,IntPtr __,IntPtr ___){if(control is 1 or 5)Stop.Set();return 0;}
    static void Report(uint state,uint error=0){var s=new Status{Type=0x10,State=state,Controls=state==4?5u:0u,Win32Exit=error};SetServiceStatus(statusHandle,ref s);}
    public static void Run(){if(!StartServiceCtrlDispatcher([new(){Name=Policy.ServiceName,Main=Main},new()]))throw new Fault(ExitCode.Unsupported,"Run service only through SCM: "+Marshal.GetLastWin32Error());}
    static void ServiceMain(uint _,IntPtr __) {
        statusHandle=RegisterServiceCtrlHandlerEx(Policy.ServiceName,Handler,IntPtr.Zero);
        if(statusHandle==IntPtr.Zero)return;
        Report(2);
        try {
            Identity.Installed();Identity.LabMachine(Program.LoadConfiguration());Report(4);
            while(!Stop.IsSet) {
                try {
                    using var gate=Program.Lock();using var engine=new Engine();var actual=engine.Inspect();var intent=IntentStore.Read();
                    if(actual.Manifest!=null) {
                        if(intent!=null && intent.Manifest.Configuration.Deployment!=actual.Manifest.Configuration.Deployment)
                            throw new Fault(ExitCode.Ownership,"Durable intent and engine deployment ownership differ");
                        // Engine metadata is authoritative for mode. A stale config
                        // must not silently switch VPNBOOK/ARMED or remove filters.
                        var resolved=Identity.Resolve(actual.Manifest.Configuration);
                        if(!actual.Complete || !Policy.Encode(resolved).SequenceEqual(Policy.Encode(actual.Manifest)))actual=engine.Reconcile(resolved);
                        if(intent?.Phase is not ("REMOVING" or "REMOVED") && !IntentStore.Agrees(intent,actual))IntentStore.Write("ACTIVE",resolved,actual.Filters);
                    } else if(intent?.Phase is "ACTIVE" or "INSTALLING") {
                        var resolved=Identity.Resolve(intent.Manifest.Configuration);
                        var restored=engine.Reconcile(resolved);
                        IntentStore.Write("ACTIVE",resolved,restored.Filters);
                    }
                } catch(Exception e) {
                    // Existing filters stay installed on identity/ownership error.
                    // A watchdog cannot guarantee zero time between deletion and
                    // repair; production activation therefore remains blocked.
                    try{var log=Path.Combine(Path.GetDirectoryName(Identity.ConfigPath)!,"guard.log");if(!File.Exists(log)||new FileInfo(log).Length<1_048_576)File.AppendAllText(log,DateTimeOffset.UtcNow+" "+e.GetType().Name+": "+e.Message+Environment.NewLine);}catch{ }
                }
                Stop.Wait(TimeSpan.FromSeconds(2));
            }
            Report(1);
        }catch{Report(1,1066);}
    }
}
