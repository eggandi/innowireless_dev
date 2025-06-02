/** 
  * @file 
  * @brief 인증서 번들 #2(새솔테크) 테스트벡터 정의
  * @date 2022-08-04 
  * @author gyun 
  */

#if 0
// SCC
const char *g_tv_bundle_2_rca = "80030081001881187263612e706c7567666573742e73736f6c746563682e696f000000000022e3337386004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808082cbc482825ec6c845c200973acc5cefdc48fa09836245bad072c26509c6d2099880803b5f1806da6cc596d0dc91e5947ee5d621d92838cd3ed56b01ef34f36e68f864f5c9fd327c5ad0f736ddcaca218a62bd50fa0badd14c32cb8f12a3f2bcc96539"; // rca
const char *g_tv_bundle_2_rca_h = "56a3484d9b26a0ae739e23525e8149ee491adbcaa343d62e40028c2ff39d84f7";
const char *g_tv_bundle_2_rca_pub_key = "02CBC482825EC6C845C200973ACC5CEFDC48FA09836245BAD072C26509C6D20998";
int g_tv_bundle_2_rca_size = 208;
const char *g_tv_bundle_2_ica = "8003008040028c2ff39d84f75881186963612e706c7567666573742e73736f6c746563682e696f9d84f7000222e342f286001483010680019a80007c8001e48003488002d4800164010180012380038300010102a0810102c06080010280012381800201008101ffc0808083c7d31ad3c9d0c89f3e1ed51b3e97c0e274cfae93c0105d78043b15981298329d8080ca5a777fae01800e6996184bdb2cc467043cd69a90ce770f2bed16d7961bb6fbfc952dbfeca0582d1404b79831f49da0ec96ddd8071805299c70d5430163b611"; // ica
const char *g_tv_bundle_2_ica_h = "7c78dcc4a94bf50d0a5039fb613c482e4271786cd00236f1a46166df32ef597a";
const char *g_tv_bundle_2_ica_pub_key = "03C7D31AD3C9D0C89F3E1ED51B3E97C0E274CFAE93C0105D78043B15981298329D";
int g_tv_bundle_2_ica_size = 206;
const char *g_tv_bundle_2_pca = "80030080a46166df32ef597a5981187063612e706c7567666573742e73736f6c746563682e696f9d84f7000222e3431486000683010680019a80007c8001e48003488002d48001640101800123800385000101010081008082e99441a0ad1524de4ecd7c8069f2393eeba76b5fa1e57f5f5e51849f31facd6380808256a228fc2dd784a9b0cdf5212309b35815b50844ec7c73991d11ca1d40a88a97808075217eb0866d0b26afdd25d2407024a26f1fb0e6dda2b0ab72988b25e05002ee278a016d55985b391d28f3fa3502cfa098907cb97b03f5d2fdbd76bb256f635a"; // pca
const char *g_tv_bundle_2_pca_h = "31dbfd64d30ca5697a5e93fa5e0d4a8ed80d692b81a6b29e3da1708a75180a01";
const char *g_tv_bundle_2_pca_pub_key = "0256A228FC2DD784A9B0CDF5212309B35815B50844EC7C73991D11CA1D40A88A97";
int g_tv_bundle_2_pca_size = 222;
const char *g_tv_bundle_2_eca = "80030080a46166df32ef597a5981186563612e706c7567666573742e73736f6c746563682e696f9d84f7000222e3433686000a83010680019a80007c8001e48003488002d4800164010180012380038400010101208140008083733c2edd2560a446dd01102d23a5bec73d370df3b14aad70ec6611844e731b7c808082c401167f38ee67e1bb04367e439735ab65fb14871515f680e206136a2c1fb9898080b99e124266279d45fd1dd780db6dbaaeb3c24792ad556ab040bca81b291441c4a60a76361d7168df615821f5fc97d982c072b096c3d4912165bce46f7608d9ed"; // eca
const char *g_tv_bundle_2_eca_h = "49d0d083469fb3c82c53dd58e34461b2fcc0a883e64544d8c366d2780c2278db";
const char *g_tv_bundle_2_eca_pub_key = "02C401167F38EE67E1BB04367E439735AB65FB14871515F680E206136A2C1FB989";
int g_tv_bundle_2_eca_size = 223;
const char *g_tv_bundle_2_ra = "80030080a46166df32ef597a55811772612e706c7567666573742e73736f6c746563682e696f9d84f7000222e3434f86000383010680019a80007c8001e48003488002d4800164010180012380038b0001010180810100008083156f91c0c57b957b3a8dda802edf3788e51309fa2a945fbffd0c2efc0da2b3a180808342dcf2f136b7f4470690a8a83606b3550a1acb50f4b198b0ec2918da4b6ba09980802bc060a20d312c217750b265df4759b394b73e28db070484e159d69bbc3530c761527ee25152576888009a0391640c662b157ec09899fe61b10eb40b2d8c7af4"; // ra
const char *g_tv_bundle_2_ra_h = "64c9a6537b95edb4315c9d76713bf5bf34f493ce5af091c5f8118973eb7f1b16";
const char *g_tv_bundle_2_ra_pub_key = "0342DCF2F136B7F4470690A8A83606B3550A1ACB50F4B198B0EC2918DA4B6BA099";
int g_tv_bundle_2_ra_size = 223;

// RSE (C00ED625C865D3C1)
const char *g_tv_bundle_2_app_cert_0_init_priv_key = "9420d7f629e244d8f3c8f69844858ccb5d06cc753b728e6af33f5ef25de8a8e4"; // dwnl_sgn.priv
const char *g_tv_bundle_2_app_cert_0_recon_priv = "cf0a6b2c57f1490b21f5af594f5e67f2ebbed623dfeeb7abc7d39639e353b903"; // 18B/900b98e686aa0650.s
const char *g_tv_bundle_2_app_cert_0_recon_pub = "";
const char *g_tv_bundle_2_app_cert_0_priv_key = "";
const char *g_tv_bundle_2_app_cert_0_pub_key = "";
const char *g_tv_bundle_2_app_cert_0 = "000301803da1708a75180a0150839d84f7000322f5768083279c80496318fe1587f37e03e8010a00017f0001820001830001870003013c9d0003013c9e0003013c9f000320409700041020407e000320409581826489b3dc41981a960819430042f0f9ede4e3ee6cf8f8e44b57c459b6c07e6fb5"; // 18B/900b98e686aa0650.cert
const char *g_tv_bundle_2_app_cert_0_h = "e51b6edec9592da279bef1243391a3f713a533d17358eed24ed3c1d2b4d45a06";
const char *g_tv_bundle_2_app_cert_0_tbs_h = "";
int g_tv_bundle_2_app_cert_0_size = ;
const char *g_tv_bundle_2_app_cert_0_cmhf_name = "";
const char *g_tv_bundle_2_app_cert_0_cmhf = "";
int g_tv_bundle_2_app_cert_0_cmhf_size = ;

const char *g_tv_bundle_2_app_cert_1_init_priv_key = ""; // rse-1/dwnl_sgn.priv
const char *g_tv_bundle_2_app_cert_1_recon_priv = ""; // rse-1/364c409476b5ffd0.s
const char *g_tv_bundle_2_app_cert_1_recon_pub = "";
const char *g_tv_bundle_2_app_cert_1_priv_key = "";
const char *g_tv_bundle_2_app_cert_1_pub_key = "";
const char *g_tv_bundle_2_app_cert_1 = ""; // rse-1/364c409476b5ffd0.cert
const char *g_tv_bundle_2_app_cert_1_h = "";
const char *g_tv_bundle_2_app_cert_1_tbs_h = "";
int g_tv_bundle_2_app_cert_1_size = ;
const char *g_tv_bundle_2_app_cert_1_cmhf_name = "";
const char *g_tv_bundle_2_app_cert_1_cmhf = "";
int g_tv_bundle_2_app_cert_1_cmhf_size = ;

// OBU (38DB109583949D23)
const char *g_tv_bundle_2_pseudonym_init_priv_key = ""; // dwnl_sgn.priv
const char *g_tv_bundle_2_pseudonym_expansion_key = ""; // sgn_expnsn.key
const char *g_tv_bundle_2_pseudonym_13a_0_recon_priv = ""; // 13A_0.s
const char *g_tv_bundle_2_pseudonym_13a_0_recon_pub = "";
const char *g_tv_bundle_2_pseudonym_13a_0_priv_key = "";
const char *g_tv_bundle_2_pseudonym_13a_0_pub_key = "";
const char *g_tv_bundle_2_pseudonym_13a_0_cert = ""; // 13A_0.cert
const char *g_tv_bundle_2_pseudonym_13a_0_cert_h = "";
const char *g_tv_bundle_2_pseudonym_13a_0_cert_tbs_h = "";
int g_tv_bundle_2_pseudonym_13a_0_cert_size = ;

const char *g_tv_bundle_2_pseudonym_13a_1_recon_priv = ""; // 13A_1.s
const char *g_tv_bundle_2_pseudonym_13a_1_recon_pub = "";
const char *g_tv_bundle_2_pseudonym_13a_1_priv_key = "";
const char *g_tv_bundle_2_pseudonym_13a_1_pub_key = "";
const char *g_tv_bundle_2_pseudonym_13a_1_cert = ""; // 13A_1.cert
const char *g_tv_bundle_2_pseudonym_13a_1_cert_h = "";
const char *g_tv_bundle_2_pseudonym_13a_1_cert_tbs_h = "";
int g_tv_bundle_2_pseudonym_13a_1_cert_size = ;
#endif
