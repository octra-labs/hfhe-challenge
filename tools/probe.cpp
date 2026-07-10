#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <array>
using namespace pvac;

static std::vector<uint8_t> rd(const char* p){
    std::ifstream in(p,std::ios::binary); in.seekg(0,std::ios::end);
    auto n=in.tellg(); in.seekg(0); std::vector<uint8_t> d(n);
    in.read((char*)d.data(),n); return d;
}
static constexpr std::array<uint8_t,16> MAG={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static uint64_t tu64(const std::vector<uint8_t>&in,size_t&pos){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[pos++]<<(8*i);return v;}

int main(int argc,char**argv){
    std::string dir = argc>1?argv[1]:".";
    auto pkb=rd((dir+"/pk.bin").c_str());
    auto ctb=rd((dir+"/secret.ct").c_str());
    auto pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
    std::cerr<<"pk ok canon="<<pk.canon_tag<<" B="<<pk.prm.B<<" powgB="<<pk.powg_B.size()<<"\n";
    size_t pos=MAG.size();
    uint64_t count=tu64(ctb,pos);
    std::cerr<<"ciphers="<<count<<"\n";
    for(uint64_t i=0;i<count;i++){
        uint64_t n=tu64(ctb,pos);
        auto C=pvac_ser::deserialize_cipher(ctb.data()+pos,n); pos+=n;
        // per-layer T_L = sum sgn*w[0]*g^idx
        std::vector<Fp> T(C.L.size(),Fp{0,0});
        std::vector<int> ecnt(C.L.size(),0);
        for(auto&e:C.E){
            Fp term=fp_mul(e.w[0],pk.powg_B[e.idx]);
            if(sgn_val(e.ch)>0) T[e.layer_id]=fp_add(T[e.layer_id],term);
            else T[e.layer_id]=fp_sub(T[e.layer_id],term);
            ecnt[e.layer_id]++;
        }
        std::cout<<"cipher "<<i<<" slots="<<C.slots<<" nL="<<C.L.size()<<" nE="<<C.E.size();
        for(size_t l=0;l<C.L.size();l++){
            std::cout<<" | L"<<l<<"("<<(C.L[l].rule==RRule::BASE?"BASE":"PROD")<<",e="<<ecnt[l]
                     <<",PC="<<C.L[l].PC.size()<<") T=0x"<<std::hex<<T[l].hi<<":"<<T[l].lo<<std::dec;
        }
        std::cout<<"\n";
    }
    return 0;
}
