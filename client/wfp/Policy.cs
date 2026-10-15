using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Walnuts.Wfp;

enum ExitCode { Success=0, Blocked=2, Incomplete=3, Identity=4, Ownership=5, Unsupported=6, Internal=7 }
sealed class Fault(ExitCode code, string message) : Exception(message) { public ExitCode Code => code; }
sealed record Configuration(int Version, Guid Deployment, string Hostname, Guid TunnelAdapter,
    Guid UnderlayAdapter, string ServiceSha256, string Mode);
sealed record Term(Guid Field, uint Type, string Value);
sealed record Rule(Guid Key, string Name, Guid Layer, ulong Weight, uint Action, Term[] Terms);
sealed record Manifest(Configuration Configuration, ulong TunnelLuid, ulong UnderlayLuid, string ServicePath,
    string ServiceSid, string DhcpSid, byte[] ServiceAppId, byte[] DhcpAppId);

static class Policy {
    public const string ServiceName="WalnutsWfpGuard";
    public const string Owner="project-walnuts/wfp-lab/v1";
    public static readonly Guid Provider=new("d8725958-c836-49c0-8c93-a77977077f91");
    public static readonly Guid Sublayer=new("33191e96-ac76-43a1-baf1-116bbd91333e");
    public const ushort SublayerWeight=0x7000;
    public const uint Block=0x1001, Permit=0x1002;
    public static readonly Guid V4=new("c38d57d1-05a7-4c33-904f-7fbceee60e82"), V6=new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    public static readonly Guid App=new("d78e1e87-8644-4ea5-9437-d809ecefc971"), User=new("af043a0a-b34d-4f86-979c-c90371af6e66"),
        NextHop=new("93ae8f5b-7f6f-4719-98c8-14e97429ef04"), Remote=new("b235ae9a-1d64-49b8-a44c-5ff3d9095045"),
        Protocol=new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), LocalPort=new("0c1ba1af-5765-453f-af22-a8f791ac775b"), RemotePort=new("c35a604d-d22b-4e1a-91b4-68f6ee674b4b");
    public static readonly JsonSerializerOptions Json=new() {WriteIndented=true, UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    public static byte[] Encode(Manifest m)=>Encoding.UTF8.GetBytes(Owner+"\n"+JsonSerializer.Serialize(m,Json));
    public static Manifest Decode(byte[] bytes) {
        string text=Encoding.UTF8.GetString(bytes);
        if(!text.StartsWith(Owner+"\n",StringComparison.Ordinal)) throw new Fault(ExitCode.Ownership,"Unknown provider ownership metadata");
        Manifest m;
        try{m=JsonSerializer.Deserialize<Manifest>(text[(Owner.Length+1)..],Json) ?? throw new Fault(ExitCode.Ownership,"Empty manifest");}
        catch(JsonException){throw new Fault(ExitCode.Ownership,"Corrupt provider metadata");}
        Validate(m.Configuration);
        if(m.TunnelLuid==0 || m.UnderlayLuid==0 || m.TunnelLuid==m.UnderlayLuid || m.ServiceAppId.Length==0 || m.DhcpAppId.Length==0)
            throw new Fault(ExitCode.Ownership,"Invalid native identity manifest");
        return m;
    }
    public static void Validate(Configuration c) {
        if(c.Version!=1 || c.Deployment==Guid.Empty || c.TunnelAdapter==Guid.Empty || c.UnderlayAdapter==Guid.Empty || c.TunnelAdapter==c.UnderlayAdapter ||
           string.IsNullOrWhiteSpace(c.Hostname) || c.Hostname.Equals("STREAM",StringComparison.OrdinalIgnoreCase) ||
           c.Mode is not ("ARMED_BLOCKED" or "VPNBOOK") || c.ServiceSha256.Length!=64 || !c.ServiceSha256.All(Uri.IsHexDigit))
            throw new Fault(ExitCode.Identity,"Invalid lab identity, mode or pinned hash; production STREAM is denied");
    }
    static Guid Key(Guid deployment,string name)=>new(SHA256.HashData(Encoding.UTF8.GetBytes(Owner+deployment.ToString("D")+name))[..16]);
    public static Rule[] Build(Manifest m) {
        Validate(m.Configuration);
        var rules=new List<Rule>();
        void Add(string name, Guid layer, ulong weight,uint action, params Term[] terms) => rules.Add(new(Key(m.Configuration.Deployment,name),name,layer,weight,action,terms));
        static Term Number(Guid field,uint type,ulong value)=>new(field,type,value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach(var (layer,suffix) in new[]{(V4,"v4"),(V6,"v6")}) {
            // Both exceptions and terminal denial are in the SAME sublayer.
            // Permits are soft: CLEAR_ACTION_RIGHT is deliberately absent.
            Add("deny-"+suffix,layer,100,Block);
            Add("daemon-udp-"+suffix,layer,500,Permit,new(App,12,Convert.ToBase64String(m.ServiceAppId)),new(User,14,m.ServiceSid),Number(NextHop,4,m.UnderlayLuid),Number(Protocol,1,17));
            Add("daemon-tcp443-"+suffix,layer,500,Permit,new(App,12,Convert.ToBase64String(m.ServiceAppId)),new(User,14,m.ServiceSid),Number(NextHop,4,m.UnderlayLuid),Number(Protocol,1,6),Number(RemotePort,2,443));
        }
        if(m.Configuration.Mode=="VPNBOOK")
            Add("tunnel-v4",V4,400,Permit,Number(NextHop,4,m.TunnelLuid));
        // No public IPv6 tunnel permit: VPNBook's namespace is IPv4-only.
        Add("dhcp-v4",V4,500,Permit,new(App,12,Convert.ToBase64String(m.DhcpAppId)),new(User,14,m.DhcpSid),Number(NextHop,4,m.UnderlayLuid),Number(Protocol,1,17),Number(LocalPort,2,68),Number(RemotePort,2,67));
        Add("loopback-v4",V4,300,Permit,new Term(Remote,0x100,"127.0.0.0/8"));
        Add("loopback-v6",V6,300,Permit,new Term(Remote,0x101,"::1/128"));
        // Only ICMPv6 link-local/multicast (NDP etc), never arbitrary link-local
        // TCP/UDP proxies. ARP is outside these IP/ALE layers.
        Add("linklocal-icmp6",V6,300,Permit,new(Remote,0x101,"fe80::/10"),Number(Protocol,1,58),Number(NextHop,4,m.UnderlayLuid));
        Add("multicast-icmp6",V6,300,Permit,new(Remote,0x101,"ff02::/16"),Number(Protocol,1,58),Number(NextHop,4,m.UnderlayLuid));
        return rules.ToArray();
    }
}
