# SnakeGX - Proof of Concept

This repository contains the Proof of Concept for SnakeGX.

The attack appears in the proceedings of ACNS 2021 (**TODO: ADD LINK PAPER**)

## Files:
- `./app/app.cpp`: contains logic of ROP chains creation and enclave analysis
- `./enclave.signed.so`: the enclave to attack, taken from [StealthDB](https://github.com/cryptograph/stealthdb) and compiled
- `./app/generateConstant.py`: this extracts the gadgets from `libc` and the `enclave`, based on `ROPgadget` (see advance section)
- `./libc.so.6`

## Preliminaries

1) Install Intel SGX Driver at commit `4505f07271ed82230fce55b8d0d820dbc7a27c5a`

```
git clone https://github.com/intel/linux-sgx-driver
cd linux-sgx-driver
git checkout 4505f07
# follow linux-sgx-driver/README.md
```

2) Install Intel SGX SDK from at commit `33f4499173497bdfdf72c5f61374c0fadc5c5365`

```
git clone https://github.com/intel/linux-sgx
cd linux-sgx
git checkout 33f44991
# follow linux-sgx/README.md
```

## How to run

```
cd <snakegx-folder>/app
LD_LIBRARY_PATH=../libc.so.6 ./app
```

## Advance section

If you are brave enough (I am soure you re!), you can try to recompile `app`.

Basically:
1. Delete `app`, i.e., `rm app/app`
2. Run `./app/generateConstant.py` and set its internal vars `pLibC`, `pLibUSgx`, and `pEnclave` in order to point to your own libc, urts, and the target enclave, respectively
3. `make` in the project root

Expected outcome: 
The `generateConstant.py` will locate the gadegts in  `pLibC`, `pLibUSgx`, and `pEnclave`; then will save their relative address in `./include/app/ExploitConstantAut.h`.
The header is used in `./app/app.cpp`, while the gadget address are adjusted at runtime.

