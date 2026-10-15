using System.Text.Json;

namespace Walnuts.Wfp;

static class Program {
    public static Configuration LoadConfiguration() {
        var info=new FileInfo(Identity.ConfigPath);
        if(info.Length>32768)throw new Fault(ExitCode.Identity,"Configuration is too large");
        var c=JsonSerializer.Deserialize<Configuration>(File.ReadAllText(info.FullName),Policy.Json) ?? throw new Fault(ExitCode.Identity,"Missing configuration");
        Policy.Validate(c);return c;
    }
    sealed class LockHandle:IDisposable {
        readonly Mutex mutex=new(false,@"Global\ProjectWalnutsWfpLabV1");
        public LockHandle(){try{if(!mutex.WaitOne(TimeSpan.FromSeconds(15)))throw new Fault(ExitCode.Incomplete,"Another operation is active");}catch(AbandonedMutexException){ }}
        public void Dispose(){mutex.ReleaseMutex();mutex.Dispose();}
    }
    public static IDisposable Lock()=>new LockHandle();
    public static void Output(object value)=>Console.WriteLine(JsonSerializer.Serialize(value,Policy.Json));
    public static int Main(string[] args) {
        try {
            if(args.Length==1 && args[0]=="self-test"){SelfTests.Run();return 0;}
            if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)throw new Fault(ExitCode.Unsupported,"Windows x64 required");
            if(args.Length==1 && args[0]=="service"){GuardService.Run();return 0;}
            if(args.Length==0)throw new Fault(ExitCode.Blocked,"Use inspect, status, verify, plan, arm or remove. Lab-only; production gate remains closed.");
            if(args[0] is "inspect" or "status" or "verify") {
                if(args.Length!=1)throw new Fault(ExitCode.Blocked,"Read commands accept no options");
                using var gate=Lock();using var engine=new Engine();var snapshot=engine.Inspect();
                bool identity=false;string? issue=null;Intent? intent=null;
                try{intent=IntentStore.Read();}catch(Exception e){issue=e.Message;}
                if(snapshot.Manifest!=null)try{Identity.Installed();identity=Policy.Encode(Identity.Resolve(snapshot.Manifest.Configuration)).SequenceEqual(Policy.Encode(snapshot.Manifest));}catch(Exception e){issue=e.Message;}
                bool intentMatches=IntentStore.Agrees(intent,snapshot);
                if(!intentMatches && (intent!=null || snapshot.Manifest!=null))issue??="Live set and durable deployment intent do not agree";
                Output(new{Schema=1,CapturedUtc=DateTimeOffset.UtcNow,FilterSetVerified=snapshot.Complete,IdentityVerified=identity,Protected=false,ProductionReady=false,
                    IntentMatches=intentMatches,Status=snapshot.Manifest==null&&intent==null?"UNINITIALIZED":snapshot.Complete&&identity&&intentMatches?"LAB_FILTER_SET_VERIFIED":"DEGRADED",
                    Caveat="ALE lab candidate: boot, BFE outage, forwarded/raw traffic and real packet isolation remain unverified.",Issue=issue,Snapshot=snapshot});
                return (int)(snapshot.Complete&&identity&&intentMatches?ExitCode.Success:ExitCode.Incomplete);
            }
            if(args[0]=="plan") {
                if(args.Length!=1)throw new Fault(ExitCode.Blocked,"Plan reads only the fixed lab configuration");
                Identity.Installed();var manifest=Identity.Resolve(LoadConfiguration());
                Output(new{Schema=1,ChangesApplied=false,ProductionReady=false,Provider=Policy.Provider,Sublayer=Policy.Sublayer,SublayerWeight=Policy.SublayerWeight,Manifest=manifest,Filters=Policy.Build(manifest)});
                return 0;
            }
            if(args[0] is not ("arm" or "remove") || args.Length!=(args[0]=="remove"?4:3) || args[1]!="--disposable-vm" || (args[0]=="remove" && args[3]!="--confirm-direct"))throw new Fault(ExitCode.Blocked,"Mutation requires operation --disposable-vm <deployment-guid>; removal also requires --confirm-direct. Never use on production.");
            if(!Guid.TryParse(args[2],out var deployment))throw new Fault(ExitCode.Identity,"Invalid explicit deployment ID");
            var config=LoadConfiguration();Identity.LabMachine(config);Identity.Installed(requireService:args[0]!="remove");
            if(config.Deployment!=deployment)throw new Fault(ExitCode.Identity,"Configuration and explicit deployment differ");
            using(var gate=Lock())using(var engine=new Engine()) {
                var saved=IntentStore.Read();
                if(saved!=null && saved.Manifest.Configuration.Deployment!=deployment)throw new Fault(ExitCode.Identity,"Durable deployment intent differs");
                if(args[0]=="remove") {
                    var current=engine.Inspect();
                    var manifest=current.Manifest??saved?.Manifest??throw new Fault(ExitCode.Ownership,"No owned deployment to remove");
                    IntentStore.Write("REMOVING",manifest,current.Filters);
                    engine.Remove(deployment);
                    IntentStore.Write("REMOVED",manifest,[]);
                    Output(new{Schema=1,Removed=true,Protected=false,ProductionReady=false,Warning="DIRECT removes VPN protection; restore captured client configuration separately."});
                }else {
                    var manifest=Identity.Resolve(config);
                    var before=engine.Inspect();
                    if(before.Manifest!=null && before.Manifest.Configuration.Deployment!=deployment)throw new Fault(ExitCode.Identity,"Existing engine deployment differs from requested identity");
                    IntentStore.Write("INSTALLING",manifest,[]);
                    var snapshot=engine.Reconcile(manifest);
                    IntentStore.Write("ACTIVE",manifest,snapshot.Filters);
                    Output(new{Schema=1,FilterSetVerified=snapshot.Complete,Protected=false,ProductionReady=false,Snapshot=snapshot});
                }
            }
            return 0;
        }catch(Fault e){Output(new{Schema=1,Error=e.Message,Code=(int)e.Code,Protected=false,ProductionReady=false});return (int)e.Code;}
        catch(Exception e){Output(new{Schema=1,Error=e.Message,Code=(int)ExitCode.Internal,Protected=false,ProductionReady=false});return (int)ExitCode.Internal;}
    }
}
