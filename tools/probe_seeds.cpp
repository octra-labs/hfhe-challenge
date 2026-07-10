#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <set>
using namespace pvac;
static std::vector<uint8_t> rd(const char*p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d(n);in.read((char*)d.data(),n);return d;}
static uint64_t tu64(const std::vector<uint8_t>&in,size_t&pos){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[pos++]<<(8*i);return v;}
int main(int c,char**v){
 std::string dir=c>1?v[1]:".";auto pkb=rd((dir+"/pk.bin").c_str());auto ctb=rd((dir+"/secret.ct").c_str());
 auto pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
 size_t pos=16;uint64_t count=tu64(ctb,pos);
 std::set<uint64_t> allnonces; int native=0,dupseed=0;
 for(uint64_t i=0;i<count;i++){uint64_t n=tu64(ctb,pos);auto C=pvac_ser::deserialize_cipher(ctb.data()+pos,n);pos+=n;
   std::set<std::pair<uint64_t,uint64_t>> seeds;
   for(auto&L:C.L){ if(ru_src(pk,L))native++;
     auto key=std::make_pair(L.seed.nonce.lo,L.seed.nonce.hi);
     if(!seeds.insert(key).second)dupseed++;
     if(!allnonces.insert(L.seed.nonce.lo^ (L.seed.nonce.hi*1099511628211ull)).second) {/*collision-ish*/}
   }
 }
 std::cout<<"native_layers="<<native<<" intra_cipher_dup_seeds="<<dupseed<<" total_layers="<<count*2<<"\n";
 return 0;}
