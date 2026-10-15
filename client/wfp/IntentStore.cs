using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Walnuts.Wfp;

sealed record InstalledId(Guid Key,ulong Id);
sealed record Intent(string Phase,Manifest Manifest,InstalledId[] LastIds,DateTimeOffset WrittenUtc);

// Durable intent aids recovery after complete object loss. It is never evidence
// that kernel enforcement exists. Explicit REMOVING/REMOVED prevents rearming
// if the owner or process terminates after an authorized native removal.
static class IntentStore {
    public static bool Agrees(Intent? intent,Snapshot snapshot)=>intent?.Phase=="ACTIVE" && snapshot.Complete && snapshot.Manifest!=null &&
        Policy.Encode(intent.Manifest).SequenceEqual(Policy.Encode(snapshot.Manifest)) && intent.LastIds.Length==snapshot.Filters.Length &&
        snapshot.Filters.All(f=>intent.LastIds.Count(i=>i.Key==f.Rule.Key && i.Id==f.Id)==1);
    static string PathName=>Path.Combine(Path.GetDirectoryName(Identity.ConfigPath)!,"intent.json");
    public static Intent? Read() {
        if(!File.Exists(PathName))return null;
        Identity.TrustedPath(PathName);
        if(new FileInfo(PathName).Length>1_048_576)throw new Fault(ExitCode.Ownership,"Intent file is too large");
        try {
            var intent=JsonSerializer.Deserialize<Intent>(File.ReadAllText(PathName),Policy.Json);
            if(intent==null || intent.Phase is not ("INSTALLING" or "ACTIVE" or "REMOVING" or "REMOVED"))throw new Fault(ExitCode.Ownership,"Unknown intent state");
            Policy.Decode(Policy.Encode(intent.Manifest));return intent;
        }catch(JsonException){throw new Fault(ExitCode.Ownership,"Corrupt intent file; objects retained");}
    }
    public static void Write(string phase,Manifest manifest,Observed[] filters) {
        var state=new Intent(phase,manifest,filters.Select(f=>new InstalledId(f.Rule.Key,f.Id)).ToArray(),DateTimeOffset.UtcNow);
        string temporary=PathName+"."+Guid.NewGuid().ToString("N")+".tmp";
        try {
            using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                JsonSerializer.Serialize(file,state,Policy.Json);file.Flush(true);
            }
            var acl=new FileInfo(temporary).GetAccessControl();
            acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));new FileInfo(temporary).SetAccessControl(acl);
            File.Move(temporary,PathName,true);
        }finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
}
