#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <iostream>
#include <vector>
#include <cstdio>
using namespace pvac;

// public per-layer invariant T_L = sum sign*w*g^idx
static void layerT(const PubKey&pk,const Cipher&C,std::vector<Fp>&T){
  T.assign(C.L.size(),Fp{0,0});
  for(auto&e:C.E){Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);
    if(sgn_val(e.ch)>0)T[e.layer_id]=fp_add(T[e.layer_id],t);else T[e.layer_id]=fp_sub(T[e.layer_id],t);}
}
static double u01(const Fp&x){ // map to [0,1) via low 53 bits
  return (double)(x.lo & ((1ull<<53)-1)) / (double)(1ull<<53);
}
int main(){
  Params prm; prm.noise_entropy_bits=128.0;
  PubKey pk; SecKey sk; keygen(prm,pk,sk);
  const int N=300;
  // Two classes: v=0 and v=0x4142... ("AB..") known plaintext block
  Fp v0=fp_from_u64(0);
  Fp v1=fp_from_u64(0x4142434445ull);
  // accumulators for a distinguisher: mean of u01(T0), u01(T1), u01(T0+T1), edge count
  auto run=[&](Fp v,const char*name){
    double sT0=0,sT1=0,sSum=0,sProd=0; long sE=0; int zeroSum=0;
    for(int i=0;i<N;i++){
      Cipher C=enc_fp_wrapped_depth(pk,sk,v,2);
      // round-trip through wire like the real artifact
      auto blob=pvac_ser::serialize_cipher(C);
      C=pvac_ser::deserialize_cipher(blob.data(),blob.size());
      std::vector<Fp>T; layerT(pk,C,T);
      Fp sum=fp_add(T[0],T[1]);
      Fp prod=fp_mul(T[0],T[1]);
      sT0+=u01(T[0]); sT1+=u01(T[1]); sSum+=u01(sum); sProd+=u01(prod);
      sE+=C.E.size();
      if(sum.lo==0&&sum.hi==0)zeroSum++;
      // sanity: decrypt must give v
      if(i==0){Fp d=dec_value(pk,sk,C); if(d.lo!=v.lo||d.hi!=v.hi){printf("DECRYPT MISMATCH\n");}}
    }
    printf("%s: meanU(T0)=%.4f meanU(T1)=%.4f meanU(T0+T1)=%.4f meanU(T0*T1)=%.4f avgEdges=%.1f zeroSum=%d\n",
      name,sT0/N,sT1/N,sSum/N,sProd/N,(double)sE/N,zeroSum);
  };
  run(v0,"v=0    ");
  run(v1,"v=known");
  return 0;
}
