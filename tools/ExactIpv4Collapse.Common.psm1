Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# No external executable/package. UInt64 covers the /0 exclusive end 2^32 safely.
if(-not ('Cpv2ExactIpv4V1.Engine' -as [type])){
 Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
namespace Cpv2ExactIpv4V1 {
 public sealed class Range { public ulong Start, End; public Range(ulong a,ulong b){Start=a;End=b;} }
 public sealed class Proof { public bool Equivalent; public int BeforeEntries,AfterEntries,UnionIntervals; public ulong AddressCount; public string IntervalSHA512; }
 public static class Engine {
  private static Range ManualRange(string text){
   string[] p=text.Split('/'); if(p.Length>2)throw new ArgumentException("CIDR_PREFIX");
   string[] o=p[0].Split('.'); if(o.Length!=4)throw new ArgumentException("IPV4_DOTTED_REQUIRED");
   ulong value=0; foreach(string s in o){byte b;if(s.Length==0||s.Length>3||(s.Length>1&&s[0]=='0'))throw new ArgumentException("IPV4_OCTET");foreach(char c in s)if(c<'0'||c>'9')throw new ArgumentException("IPV4_DIGITS");if(!Byte.TryParse(s,out b))throw new ArgumentException("IPV4_OCTET");value=value*256+b;}
   int prefix=32; if(p.Length==2){if(p[1].Length==0||p[1].Length>2||(p[1].Length>1&&p[1][0]=='0'))throw new ArgumentException("CIDR_PREFIX");foreach(char c in p[1])if(c<'0'||c>'9')throw new ArgumentException("CIDR_PREFIX");if(!Int32.TryParse(p[1],out prefix)||prefix<0||prefix>32)throw new ArgumentException("CIDR_PREFIX");}
   ulong size=1UL<<(32-prefix); ulong start=value-(value%size); return new Range(start,start+size-1);
  }
  private static string Address(ulong n){return ((n>>24)&255)+"."+((n>>16)&255)+"."+((n>>8)&255)+"."+(n&255);}
  public static string[] Collapse(string[] values){
   List<Range> sorted=new List<Range>();foreach(string s in values)sorted.Add(ManualRange(s));
   sorted.Sort(delegate(Range a,Range b){int c=a.Start.CompareTo(b.Start);return c!=0?c:a.End.CompareTo(b.End);});
   List<Range> merged=new List<Range>();foreach(Range r in sorted){if(merged.Count==0||r.Start>merged[merged.Count-1].End+1)merged.Add(new Range(r.Start,r.End));else if(r.End>merged[merged.Count-1].End)merged[merged.Count-1].End=r.End;}
   List<string> output=new List<string>();foreach(Range r in merged){ulong cursor=r.Start;while(cursor<=r.End){ulong remain=r.End-cursor+1,size=1;while(size<4294967296UL && size*2<=remain && cursor%(size*2)==0)size*=2;int prefix=32;for(ulong n=size;n>1;n>>=1)prefix--;output.Add(Address(cursor)+"/"+prefix);cursor+=size;}}
   return output.ToArray();
  }
  // Independent proof: a different parser (.NET IPAddress) and endpoint sweep,
  // rather than reusing the production sort/merge/collapse result as its oracle.
  private static Range ProofRange(string text){
   string[] p=text.Split('/');if(p.Length>2)throw new ArgumentException("PROOF_PREFIX");IPAddress ip;
   if(p[0].Split('.').Length!=4||!IPAddress.TryParse(p[0],out ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)throw new ArgumentException("PROOF_IPV4");
   byte[] b=ip.GetAddressBytes();ulong number=((ulong)b[0]<<24)|((ulong)b[1]<<16)|((ulong)b[2]<<8)|b[3];int prefix=p.Length==1?32:Int32.Parse(p[1]);if(prefix<0||prefix>32)throw new ArgumentException("PROOF_PREFIX");
   ulong hostMask=prefix==32?0UL:((1UL<<(32-prefix))-1);ulong start=number&(~hostMask&4294967295UL);return new Range(start,start|hostMask);
  }
  private static void Event(SortedDictionary<ulong,long> events,ulong at,long delta){long old;events.TryGetValue(at,out old);events[at]=old+delta;}
  private static List<Range> Sweep(string[] values){
   SortedDictionary<ulong,long> events=new SortedDictionary<ulong,long>();foreach(string s in values){Range r=ProofRange(s);Event(events,r.Start,1);Event(events,r.End+1,-1);}
   long active=0;ulong start=0;List<Range> result=new List<Range>();foreach(KeyValuePair<ulong,long> e in events){long next=active+e.Value;if(active==0&&next>0)start=e.Key;if(active>0&&next==0)result.Add(new Range(start,e.Key-1));if(next<0)throw new ArgumentException("PROOF_NEGATIVE_DEPTH");active=next;}if(active!=0)throw new ArgumentException("PROOF_UNCLOSED");return result;
  }
  public static Proof Verify(string[] before,string[] after){
   List<Range> a=Sweep(before),b=Sweep(after);if(a.Count!=b.Count)throw new ArgumentException("EXACT_COVERAGE_INTERVAL_COUNT");
   ulong count=0;StringBuilder canonical=new StringBuilder();for(int n=0;n<a.Count;n++){if(a[n].Start!=b[n].Start||a[n].End!=b[n].End)throw new ArgumentException("EXACT_COVERAGE_CHANGED");count+=a[n].End-a[n].Start+1;canonical.Append(a[n].Start).Append('-').Append(a[n].End).Append('\n');}
   string hash;using(SHA512 sha=SHA512.Create()){hash=BitConverter.ToString(sha.ComputeHash(Encoding.ASCII.GetBytes(canonical.ToString()))).Replace("-","").ToLowerInvariant();}
   return new Proof{Equivalent=true,BeforeEntries=before.Length,AfterEntries=after.Length,UnionIntervals=a.Count,AddressCount=count,IntervalSHA512=hash};
  }
 }
}
'@
}
function Get-ExactIpv4Collapse {
 [CmdletBinding()]param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Values)
 $collapsed=[Cpv2ExactIpv4V1.Engine]::Collapse($Values)
 $proof=[Cpv2ExactIpv4V1.Engine]::Verify($Values,$collapsed)
 [pscustomobject]@{Values=$collapsed;Proof=$proof;ProofMethod='independent-net-ipaddress-endpoint-sweep-v1'}
}
function Test-ExactIpv4Coverage {
 [CmdletBinding()]param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Before,[Parameter(Mandatory)][AllowEmptyCollection()][string[]]$After)
 [Cpv2ExactIpv4V1.Engine]::Verify($Before,$After)
}
Export-ModuleMember -Function @('Get-ExactIpv4Collapse','Test-ExactIpv4Coverage')
