using System.Runtime.InteropServices;

namespace Walnuts.Wfp;

sealed record Observed(Rule Rule, ulong Id);
sealed record Snapshot(Manifest? Manifest, Observed[] Filters, string[] Missing) {
    public bool Complete=>Manifest!=null && Missing.Length==0;
}

sealed class Engine:IDisposable {
    readonly IntPtr handle;
    bool inTransaction;
    public Engine(){Native.AssertAbi();Native.Check(Native.FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out handle),"Open local BFE");}
    public void Dispose()=>Native.FwpmEngineClose0(handle);
    static byte[] Metadata(Manifest m)=>Policy.Encode(m);
    void AssertAcl(Guid key,int kind) {
        IntPtr sd,dacl;
        uint result=kind switch {
            0=>Native.FwpmProviderGetSecurityInfoByKey0(handle,ref key,4,IntPtr.Zero,IntPtr.Zero,out dacl,IntPtr.Zero,out sd),
            1=>Native.FwpmSubLayerGetSecurityInfoByKey0(handle,ref key,4,IntPtr.Zero,IntPtr.Zero,out dacl,IntPtr.Zero,out sd),
            _=>Native.FwpmFilterGetSecurityInfoByKey0(handle,ref key,4,IntPtr.Zero,IntPtr.Zero,out dacl,IntPtr.Zero,out sd)};
        Native.Check(result,"Read object DACL");
        try {
            if(sd==IntPtr.Zero || dacl==IntPtr.Zero)throw new Fault(ExitCode.Ownership,"Missing object DACL");
            uint length=Native.GetSecurityDescriptorLength(sd);
            if(length==0 || length>65536)throw new Fault(ExitCode.Ownership,"Invalid DACL descriptor length");
            byte[] bytes=new byte[length];Marshal.Copy(sd,bytes,0,bytes.Length);
            var descriptor=new System.Security.AccessControl.RawSecurityDescriptor(bytes,0);
            var acl=descriptor.DiscretionaryAcl;
            if(acl==null || acl.Count!=2)throw new Fault(ExitCode.Ownership,"Object DACL differs");
            var trustees=new HashSet<string>();
            foreach(System.Security.AccessControl.GenericAce ace in acl) {
                if(ace is not System.Security.AccessControl.CommonAce c || c.AceQualifier!=System.Security.AccessControl.AceQualifier.AccessAllowed || c.AceFlags!=0 || c.AccessMask is not (0x10000000 or 0x000f07ff) ||
                   c.SecurityIdentifier.Value is not ("S-1-5-18" or "S-1-5-32-544"))throw new Fault(ExitCode.Ownership,"Unrecognized object access rule");
                trustees.Add(c.SecurityIdentifier.Value);
            }
            if(trustees.Count!=2)throw new Fault(ExitCode.Ownership,"Missing privileged trustee");
        } finally{Native.FwpmFreeMemory0(ref sd);}
    }
    public Snapshot Inspect() {
        if(inTransaction)return InspectCore();
        Native.Check(Native.FwpmTransactionBegin0(handle,1),"Begin read-only inspection transaction");
        inTransaction=true;
        try{var snapshot=InspectCore();Native.Check(Native.FwpmTransactionCommit0(handle),"Commit inspection");return snapshot;}
        catch{Native.FwpmTransactionAbort0(handle);throw;}
        finally{inTransaction=false;}
    }
    Snapshot InspectCore() {
        var pk=Policy.Provider;uint status=Native.FwpmProviderGetByKey0(handle,ref pk,out var providerPtr);
        Manifest? manifest=null;
        if(status!=0x80320005) {
            Native.Check(status,"Get owned provider");
            try {
                var provider=Marshal.PtrToStructure<Native.Provider>(providerPtr);
                manifest=Policy.Decode(Native.Bytes(provider.Data));
                if(provider.Flags!=1 || Marshal.PtrToStringUni(provider.Service)!=Policy.ServiceName)
                    throw new Fault(ExitCode.Ownership,"Provider persistence/service binding differs");
                AssertAcl(pk,0);
            } finally{Native.FwpmFreeMemory0(ref providerPtr);}
        }
        var sk=Policy.Sublayer;status=Native.FwpmSubLayerGetByKey0(handle,ref sk,out var subPtr);
        bool subPresent=status==0;
        if(status!=0x80320007) {
            Native.Check(status,"Get owned sublayer");
            try {
                var sub=Marshal.PtrToStructure<Native.Sublayer>(subPtr);
                if(manifest==null || sub.Provider==IntPtr.Zero || Marshal.PtrToStructure<Guid>(sub.Provider)!=Policy.Provider || sub.Flags!=1 || sub.Weight!=Policy.SublayerWeight || !Native.Bytes(sub.Data).SequenceEqual(Metadata(manifest)))
                    throw new Fault(ExitCode.Ownership,"Sublayer identity or properties differ");
                AssertAcl(sk,1);
            } finally{Native.FwpmFreeMemory0(ref subPtr);}
        }
        var observed=new List<Observed>();
        var expected=manifest==null ? [] : Policy.Build(manifest);
        Native.Check(Native.FwpmFilterCreateEnumHandle0(handle,IntPtr.Zero,out var enumeration),"Enumerate filters");
        try {
            while(true) {
                Native.Check(Native.FwpmFilterEnum0(handle,enumeration,256,out var entries,out uint count),"Read filters");
                try {
                    for(int i=0;i<count;i++) {
                        var f=Marshal.PtrToStructure<Native.Filter>(Marshal.ReadIntPtr(entries,i*IntPtr.Size));
                        bool owned=f.Provider!=IntPtr.Zero && Marshal.PtrToStructure<Guid>(f.Provider)==Policy.Provider;
                        bool keyCollision=expected.Any(r=>r.Key==f.Key);
                        if(!owned && f.Sublayer!=Policy.Sublayer && !keyCollision)continue;
                        if(manifest==null || !owned || !subPresent)throw new Fault(ExitCode.Ownership,"Orphaned or foreign filter references Walnuts identity");
                        var rule=expected.SingleOrDefault(r=>r.Key==f.Key) ?? throw new Fault(ExitCode.Ownership,"Unexpected filter in Walnuts provider/sublayer");
                        AssertFilter(f,rule,manifest);
                        AssertAcl(f.Key,2);
                        observed.Add(new(rule,f.Id));
                    }
                } finally{Native.FwpmFreeMemory0(ref entries);}
                if(count==0)break;
            }
        } finally{Native.FwpmFilterDestroyEnumHandle0(handle,enumeration);}
        var missing=expected.Where(r=>!observed.Any(o=>o.Rule.Key==r.Key)).Select(r=>r.Name).ToList();
        if(manifest!=null && !subPresent)missing.Add("sublayer");
        return new(manifest,observed.ToArray(),missing.ToArray());
    }
    public static void AssertFilter(Native.Filter f,Rule rule,Manifest m) {
        if(f.Key!=rule.Key || f.Provider==IntPtr.Zero || Marshal.PtrToStructure<Guid>(f.Provider)!=Policy.Provider || f.Sublayer!=Policy.Sublayer ||
           f.Layer!=rule.Layer || f.Flags!=1 || f.Action.Type!=rule.Action || f.Action.Key!=Guid.Empty || f.ContextLow!=0 ||
           f.Count!=rule.Terms.Length || f.Weight.Type!=4 || f.Weight.Bits==0 || Marshal.ReadInt64((IntPtr)f.Weight.Bits)!=(long)rule.Weight ||
           !Native.Bytes(f.Data).SequenceEqual(Metadata(m)))throw new Fault(ExitCode.Ownership,"Filter properties changed: "+rule.Name);
        if(f.Count>0 && f.Conditions==IntPtr.Zero)throw new Fault(ExitCode.Ownership,"Missing native condition array");
        using var arena=new Arena();
        for(int i=0;i<f.Count;i++) {
            var current=Marshal.PtrToStructure<Native.Condition>(f.Conditions+i*Marshal.SizeOf<Native.Condition>());
            var wanted=arena.Condition(rule.Terms[i]);
            if(current.Field!=wanted.Field || current.Match!=0 || current.Value.Type!=wanted.Value.Type || !SameValue(current.Value,wanted.Value))
                throw new Fault(ExitCode.Ownership,"Filter condition changed: "+rule.Name);
        }
    }
    static bool SameValue(Native.Value a,Native.Value b) {
        if(a.Type==1)return (byte)a.Bits==(byte)b.Bits;
        if(a.Type==2)return (ushort)a.Bits==(ushort)b.Bits;
        if(a.Type==3)return (uint)a.Bits==(uint)b.Bits;
        if(a.Bits==0 || b.Bits==0)return false;
        if(a.Type==4)return Marshal.ReadInt64((IntPtr)a.Bits)==Marshal.ReadInt64((IntPtr)b.Bits);
        if(a.Type is 12 or 14)return Native.Bytes(Marshal.PtrToStructure<Native.Blob>((IntPtr)a.Bits)).SequenceEqual(Native.Bytes(Marshal.PtrToStructure<Native.Blob>((IntPtr)b.Bits)));
        if(a.Type==0x100)return Marshal.ReadInt64((IntPtr)a.Bits)==Marshal.ReadInt64((IntPtr)b.Bits);
        if(a.Type==0x101){byte[] x=new byte[17],y=new byte[17];Marshal.Copy((IntPtr)a.Bits,x,0,17);Marshal.Copy((IntPtr)b.Bits,y,0,17);return x.SequenceEqual(y);}
        return false;
    }
    public Snapshot Reconcile(Manifest requested) {
        Native.Check(Native.FwpmTransactionBegin0(handle,0),"Begin install transaction");
        inTransaction=true;
        try {
            var old=Inspect();
            if(old.Complete && Policy.Encode(old.Manifest!).SequenceEqual(Policy.Encode(requested))) {
                Native.Check(Native.FwpmTransactionCommit0(handle),"Commit unchanged reconciliation");return old;
            }
            if(old.Manifest!=null) {
                if(old.Manifest.Configuration.Deployment!=requested.Configuration.Deployment ||
                   old.Manifest.Configuration.Hostname!=requested.Configuration.Hostname)
                    throw new Fault(ExitCode.Identity,"Another deployment owns the provider");
                // Verify every surviving object before a transactional replacement.
                // Missing objects are repaired; mismatched objects are never adopted.
                Delete(old);
            }
            using var a=new Arena();
            var sd=a.Descriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
            var provider=new Native.Provider{Key=Policy.Provider,Display=new(){Name=a.Text("Walnuts WFP lab"),Description=a.Text(Policy.Owner)},Flags=1,Data=a.Blob(Metadata(requested)),Service=a.Text(Policy.ServiceName)};
            Native.Check(Native.FwpmProviderAdd0(handle,ref provider,sd),"Add provider");
            var sub=new Native.Sublayer{Key=Policy.Sublayer,Display=new(){Name=a.Text("Walnuts WFP lab"),Description=a.Text(Policy.Owner)},Flags=1,Provider=a.Struct(Policy.Provider),Data=a.Blob(Metadata(requested)),Weight=Policy.SublayerWeight};
            Native.Check(Native.FwpmSubLayerAdd0(handle,ref sub,sd),"Add sublayer");
            foreach(var rule in Policy.Build(requested)) {
                var filter=a.Filter(rule,requested);
                Native.Check(Native.FwpmFilterAdd0(handle,ref filter,sd,out _),"Add filter "+rule.Name);
            }
            var staged=Inspect();
            if(!staged.Complete)throw new Fault(ExitCode.Incomplete,"Staged filter set incomplete");
            Native.Check(Native.FwpmTransactionCommit0(handle),"Commit install transaction");
        }catch{Native.FwpmTransactionAbort0(handle);throw;}
        finally{inTransaction=false;}
        var live=Inspect();if(!live.Complete)throw new Fault(ExitCode.Incomplete,"Committed filters could not be verified");return live;
    }
    void Delete(Snapshot snapshot) {
        foreach(var item in snapshot.Filters){var key=item.Rule.Key;Native.Check(Native.FwpmFilterDeleteByKey0(handle,ref key),"Remove verified filter");}
        var sk=Policy.Sublayer;uint status=Native.FwpmSubLayerDeleteByKey0(handle,ref sk);
        if(status!=0x80320007)Native.Check(status,"Remove verified sublayer");
        var pk=Policy.Provider;Native.Check(Native.FwpmProviderDeleteByKey0(handle,ref pk),"Remove verified provider");
    }
    public void Remove(Guid deployment) {
        Native.Check(Native.FwpmTransactionBegin0(handle,0),"Begin removal transaction");
        inTransaction=true;
        try {
            var old=Inspect();
            if(old.Manifest==null)throw new Fault(ExitCode.Ownership,"No owned deployment exists");
            if(old.Manifest.Configuration.Deployment!=deployment)throw new Fault(ExitCode.Identity,"Explicit deployment ID mismatch");
            Delete(old);Native.Check(Native.FwpmTransactionCommit0(handle),"Commit removal transaction");
        }catch{Native.FwpmTransactionAbort0(handle);throw;}
        finally{inTransaction=false;}
        if(Inspect().Manifest!=null)throw new Fault(ExitCode.Incomplete,"Removal could not be verified");
    }
}
