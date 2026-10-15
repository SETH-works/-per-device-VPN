using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;

namespace Walnuts.Wfp;

// Windows SDK fwptypes.h/fwpmtypes.h, x64 ABI. Self-test checks every used
// structure size/offset before any engine access. No unchecked manual offsets.
static class Native {
    [DllImport("advapi32.dll")]public static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [StructLayout(LayoutKind.Sequential)] public struct Blob {public uint Size; public IntPtr Data;}
    [StructLayout(LayoutKind.Sequential)] public struct Display {public IntPtr Name,Description;}
    [StructLayout(LayoutKind.Explicit,Size=16)] public struct Value {[FieldOffset(0)]public uint Type;[FieldOffset(8)]public ulong Bits;}
    [StructLayout(LayoutKind.Sequential)] public struct Condition {public Guid Field;public uint Match;public Value Value;}
    [StructLayout(LayoutKind.Sequential)] public struct Action {public uint Type;public Guid Key;}
    [StructLayout(LayoutKind.Sequential)] public struct Filter {
        public Guid Key;public Display Display;public uint Flags;public IntPtr Provider;public Blob Data;
        public Guid Layer,Sublayer;public Value Weight;public uint Count;public IntPtr Conditions;
        public Action Action;public ulong ContextLow,ContextHigh;public IntPtr Reserved;public ulong Id;public Value EffectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Provider {public Guid Key;public Display Display;public uint Flags;public Blob Data;public IntPtr Service;}
    [StructLayout(LayoutKind.Sequential)] public struct Sublayer {public Guid Key;public Display Display;public uint Flags;public IntPtr Provider;public Blob Data;public ushort Weight;}
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]public static extern uint FwpmEngineOpen0(string? server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmTransactionBegin0(IntPtr e,uint flags);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmTransactionCommit0(IntPtr e);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmTransactionAbort0(IntPtr e);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmProviderAdd0(IntPtr e,ref Provider value,IntPtr sd);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmSubLayerAdd0(IntPtr e,ref Sublayer value,IntPtr sd);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmFilterAdd0(IntPtr e,ref Filter value,IntPtr sd,out ulong id);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmProviderGetByKey0(IntPtr e,ref Guid key,out IntPtr value);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmSubLayerGetByKey0(IntPtr e,ref Guid key,out IntPtr value);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmProviderDeleteByKey0(IntPtr e,ref Guid key);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmSubLayerDeleteByKey0(IntPtr e,ref Guid key);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmFilterDeleteByKey0(IntPtr e,ref Guid key);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmFilterCreateEnumHandle0(IntPtr e,IntPtr template,out IntPtr handle);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmFilterEnum0(IntPtr e,IntPtr handle,uint requested,out IntPtr entries,out uint count);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmFilterDestroyEnumHandle0(IntPtr e,IntPtr handle);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmProviderGetSecurityInfoByKey0(IntPtr e,ref Guid key,uint info,IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr sd);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmSubLayerGetSecurityInfoByKey0(IntPtr e,ref Guid key,uint info,IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr sd);
    [DllImport("fwpuclnt.dll")]public static extern uint FwpmFilterGetSecurityInfoByKey0(IntPtr e,ref Guid key,uint info,IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr sd);
    [DllImport("fwpuclnt.dll")]public static extern void FwpmFreeMemory0(ref IntPtr pointer);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]public static extern uint FwpmGetAppIdFromFileName0(string path,out IntPtr blob);
    public static void Check(uint code,string operation) {if(code!=0)throw new Fault(ExitCode.Internal,$"{operation}: Windows error 0x{code:x8}");}
    public static byte[] Bytes(Blob blob) {
        if(blob.Size>1_048_576 || (blob.Size>0 && blob.Data==IntPtr.Zero))throw new Fault(ExitCode.Ownership,"Invalid native blob");
        byte[] result=new byte[blob.Size];if(result.Length>0)Marshal.Copy(blob.Data,result,0,result.Length);return result;
    }
    public static byte[] AppId(string path) {
        Check(FwpmGetAppIdFromFileName0(path,out var p),"Get application identity");
        try{return Bytes(Marshal.PtrToStructure<Blob>(p));}finally{FwpmFreeMemory0(ref p);}
    }
    public static void AssertAbi() {
        foreach(var (type,size) in new[]{(typeof(Blob),16),(typeof(Value),16),(typeof(Condition),40),(typeof(Action),20),(typeof(Filter),200),(typeof(Provider),64),(typeof(Sublayer),72)})
            if(IntPtr.Size!=8 || Marshal.SizeOf(type)!=size)throw new Fault(ExitCode.Unsupported,"Unsupported WFP ABI: "+type.Name);
        if(Marshal.OffsetOf<Filter>(nameof(Filter.Conditions)).ToInt32()!=120 || Marshal.OffsetOf<Filter>(nameof(Filter.Id)).ToInt32()!=176)
            throw new Fault(ExitCode.Unsupported,"WFP filter ABI offset mismatch");
    }
}

sealed class Arena:IDisposable {
    readonly List<IntPtr> allocations=[];
    public IntPtr Bytes(byte[] data){var p=Marshal.AllocHGlobal(Math.Max(data.Length,1));allocations.Add(p);if(data.Length>0)Marshal.Copy(data,0,p,data.Length);return p;}
    public IntPtr Struct<T>(T item)where T:struct{var p=Bytes(new byte[Marshal.SizeOf<T>()]);Marshal.StructureToPtr(item,p,false);return p;}
    public IntPtr Text(string text)=>Bytes(Encoding.Unicode.GetBytes(text+"\0"));
    public Native.Blob Blob(byte[] bytes)=>new(){Size=(uint)bytes.Length,Data=Bytes(bytes)};
    public IntPtr Descriptor(string sddl) {var sd=new RawSecurityDescriptor(sddl);var bytes=new byte[sd.BinaryLength];sd.GetBinaryForm(bytes,0);return Bytes(bytes);}
    public Native.Condition Condition(Term t) {
        var value=new Native.Value{Type=t.Type};
        value.Bits=t.Type switch {
            1 or 2 or 3=>ulong.Parse(t.Value,System.Globalization.CultureInfo.InvariantCulture),
            4=>(ulong)Struct(ulong.Parse(t.Value,System.Globalization.CultureInfo.InvariantCulture)),
            12=>(ulong)Struct(Blob(Convert.FromBase64String(t.Value))),
            14=>(ulong)Struct(Blob(SecurityDescriptorBytes(t.Value))),
            0x100=>(ulong)Bytes(V4Mask(t.Value)),
            0x101=>(ulong)Bytes(V6Mask(t.Value)),
            _=>throw new Fault(ExitCode.Internal,"Unsupported condition type")};
        return new(){Field=t.Field,Match=0,Value=value};
    }
    public static byte[] SecurityDescriptorBytes(string serviceSid){var sd=new RawSecurityDescriptor($"D:(A;;1;;;{serviceSid})");byte[] bytes=new byte[sd.BinaryLength];sd.GetBinaryForm(bytes,0);return bytes;}
    static byte[] V6Mask(string prefix){var parts=prefix.Split('/');var address=System.Net.IPAddress.Parse(parts[0]).GetAddressBytes();byte[] bytes=new byte[17];address.CopyTo(bytes,0);bytes[16]=byte.Parse(parts[1]);return bytes;}
    static byte[] V4Mask(string prefix){var parts=prefix.Split('/');uint address=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(System.Net.IPAddress.Parse(parts[0]).GetAddressBytes());uint mask=uint.MaxValue<<(32-int.Parse(parts[1]));return BitConverter.GetBytes(address).Concat(BitConverter.GetBytes(mask)).ToArray();}
    public Native.Filter Filter(Rule rule,Manifest manifest) {
        var conditions=rule.Terms.Select(Condition).ToArray();var p=Bytes(new byte[conditions.Length*Marshal.SizeOf<Native.Condition>()]);
        for(int i=0;i<conditions.Length;i++)Marshal.StructureToPtr(conditions[i],p+i*Marshal.SizeOf<Native.Condition>(),false);
        return new(){Key=rule.Key,Display=new(){Name=Text(rule.Name),Description=Text(Policy.Owner)},Flags=1,Provider=Struct(Policy.Provider),
            Data=Blob(Policy.Encode(manifest)),Layer=rule.Layer,Sublayer=Policy.Sublayer,Weight=new(){Type=4,Bits=(ulong)Struct(rule.Weight)},
            Count=(uint)conditions.Length,Conditions=p,Action=new(){Type=rule.Action}};
    }
    public void Dispose(){foreach(var p in allocations)Marshal.FreeHGlobal(p);allocations.Clear();}
}
