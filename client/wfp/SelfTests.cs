using System.Runtime.InteropServices;

namespace Walnuts.Wfp;

static class SelfTests {
    public static Manifest Fixture(string mode="ARMED_BLOCKED")=>new(new(1,new("ec2173e9-996f-4341-8a96-4bb692848903"),"WALNUTS-LAB",new("3ce4918b-52f0-47f2-aaab-107496bf4211"),new("e6a68ec7-053f-412e-9aaf-158a257ea8dd"),new string('A',64),mode),111,222,
        @"C:\Program Files\Tailscale\tailscaled.exe","S-1-5-80-1-2-3-4-5","S-1-5-80-5-4-3-2-1",[1,2,3,4],[5,6,7,8]);
    public static void Run() {
        var passed=new List<string>();
        void Check(string name,bool valid){if(!valid)throw new Exception("Self-test failed: "+name);passed.Add(name);}
        void Reject(string name,System.Action operation){try{operation();}catch(Fault){passed.Add(name);return;}throw new Exception("Self-test failed to reject: "+name);}
        Native.AssertAbi();passed.Add("x64 native sizes and offsets");
        var manifest=Fixture();var rules=Policy.Build(manifest);
        Check("deterministic filter identifiers",rules.Select(r=>r.Key).SequenceEqual(Policy.Build(manifest).Select(r=>r.Key)));
        Check("unique identifiers",rules.Select(r=>r.Key).Distinct().Count()==rules.Length);
        Check("two unconditional family denials",rules.Count(r=>r.Action==Policy.Block && r.Terms.Length==0)==2);
        Check("unknown adapters remain within unconditional deny",rules.Where(r=>r.Action==Policy.Block).All(r=>r.Terms.Length==0));
        Check("profiles do not weaken boundary",rules.All(r=>r.Terms.All(t=>t.Field!=Guid.Empty)));
        Check("ARMED has no application tunnel exception",rules.All(r=>r.Name!="tunnel-v4"));
        var vpn=Policy.Build(Fixture("VPNBOOK"));
        Check("VPNBOOK permits only v4 tunnel LUID",vpn.Single(r=>r.Name=="tunnel-v4").Terms.SequenceEqual(new[]{new Term(Policy.NextHop,4,"111")}));
        Check("no native public IPv6 tunnel permit",vpn.All(r=>r.Name!="tunnel-v6"));
        foreach(var r in rules.Where(r=>r.Name.StartsWith("daemon-",StringComparison.Ordinal))) {
            Check(r.Name+" image and service binding",r.Terms.Any(t=>t.Field==Policy.App)&&r.Terms.Any(t=>t.Field==Policy.User)&&r.Terms.Any(t=>t.Field==Policy.NextHop));
            Check(r.Name+" soft exception precedes deny",r.Weight>100 && r.Action==Policy.Permit);
        }
        Check("DERP TCP port restriction",rules.Where(r=>r.Name.Contains("tcp443")).All(r=>r.Terms.Any(t=>t.Field==Policy.RemotePort&&t.Value=="443")));
        Check("DHCP local and remote port scope",rules.Single(r=>r.Name=="dhcp-v4").Terms.Any(t=>t.Field==Policy.LocalPort&&t.Value=="68"));
        Check("manifest round trip",Policy.Encode(Policy.Decode(Policy.Encode(manifest))).SequenceEqual(Policy.Encode(manifest)));
        Reject("foreign ownership metadata",()=>Policy.Decode([1,2,3]));
        Reject("production hostname",()=>Policy.Validate(manifest.Configuration with{Hostname="STREAM"}));
        Reject("invalid adapter identity",()=>Policy.Validate(manifest.Configuration with{UnderlayAdapter=manifest.Configuration.TunnelAdapter}));
        Reject("invalid mode",()=>Policy.Validate(manifest.Configuration with{Mode="DIRECT"}));
        var observed=rules.Select((r,i)=>new Observed(r,(ulong)i+1)).ToArray();
        var snapshot=new Snapshot(manifest,observed,[]);
        var intent=new Intent("ACTIVE",manifest,observed.Select(o=>new InstalledId(o.Rule.Key,o.Id)).ToArray(),DateTimeOffset.UtcNow);
        Check("durable intent plus actual complete set agrees",IntentStore.Agrees(intent,snapshot));
        Check("stale journal never proves live filters",!IntentStore.Agrees(intent,new(null,[],[])));
        Check("missing journal does not prove deployment ownership",!IntentStore.Agrees(null,snapshot));
        Check("explicit removal intent prevents automatic active attestation",!IntentStore.Agrees(intent with{Phase="REMOVING"},snapshot));
        // Real native marshaling and readback, without loading/opening WFP.
        foreach(var rule in vpn) {
            using var a=new Arena();var filter=a.Filter(rule,Fixture("VPNBOOK"));Engine.AssertFilter(filter,rule,Fixture("VPNBOOK"));
            Check(rule.Name+" persistent and soft",filter.Flags==1);
            filter.Flags|=8;Reject(rule.Name+" rejects hard permit/property drift",()=>Engine.AssertFilter(filter,rule,Fixture("VPNBOOK")));
        }
        using(var a=new Arena()) {
            var rule=rules.Single(r=>r.Name=="dhcp-v4");var f=a.Filter(rule,manifest);
            var c=Marshal.PtrToStructure<Native.Condition>(f.Conditions);c.Match=10;Marshal.StructureToPtr(c,f.Conditions,false);
            Reject("condition operator tampering",()=>Engine.AssertFilter(f,rule,manifest));
        }
        Program.Output(new{Offline=true,NativeEngineOpened=false,PacketTestsPerformed=false,Passed=passed.Count,Tests=passed});
    }
}
