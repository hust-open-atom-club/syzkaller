// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_LOONG64_SYZOS_H
#define EXECUTOR_COMMON_KVM_LOONG64_SYZOS_H

// Guest code running inside Loong64 KVM.
// This slice implements UEXIT, CODE, IOCSR_WRITE, CSRR, CSRW, and MEMOP.

#include <linux/kvm.h>

#include "common_kvm_syzos.h"
#include "kvm.h"

// Remember these constants must match those in sys/linux/dev_kvm_loong64.txt.
typedef enum {
	SYZOS_API_UEXIT = 0,
	SYZOS_API_CODE = 10,
	SYZOS_API_IOCSR_WRITE = 100,
	SYZOS_API_CSRR = 101,
	SYZOS_API_CSRW = 102,
	SYZOS_API_MEMOP = 110,
	SYZOS_API_STOP, // Must be the last one
} syzos_api_id;

struct api_call_code {
	struct api_call_header header;
	uint32 insns[];
};

GUEST_CODE static void guest_uexit(uint64 exit_code);
GUEST_CODE static void guest_execute_code(uint32* insns, uint64 size);
GUEST_CODE static void guest_iocsr_write(uint64 addr, uint64 value);
GUEST_CODE static void guest_handle_csrr(uint64 cpu, uint32 csr);
GUEST_CODE static void guest_handle_csrw(uint64 cpu, uint32 csr, uint64 value);
GUEST_CODE static void guest_handle_memop(uint64 cpu, struct api_call_5* cmd);
GUEST_CODE static void sync_guest_insns(void);

// Main guest function that interprets the host-provided API command stream.
// Use if-statements rather than switch to avoid jump tables that need data
// relocations (see https://github.com/google/syzkaller/issues/5565).
__attribute__((used))
GUEST_CODE static void
guest_main(uint64 size, uint64 cpu)
{
	uint64 addr = LOONG64_ADDR_USER_CODE + cpu * LOONG64_KVM_PAGE_SIZE;

	while (size >= sizeof(struct api_call_header)) {
		struct api_call_header* cmd = (struct api_call_header*)addr;
		uint64 call = cmd->call;
		uint64 cmd_size = cmd->size;
		if (call >= SYZOS_API_STOP)
			return;
		if (cmd_size < sizeof(struct api_call_header) || cmd_size > size)
			return;
		if (call == SYZOS_API_UEXIT) {
			if (cmd_size < sizeof(struct api_call_1))
				return;
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			uint64 arg = ccmd->arg;
			guest_uexit(arg);
		} else if (call == SYZOS_API_CODE) {
			// The command payload ends with the fixed four-byte return instruction.
			if (cmd_size < sizeof(struct api_call_header) + sizeof(uint32) ||
			    (cmd_size - sizeof(struct api_call_header)) % sizeof(uint32))
				return;
			struct api_call_code* ccmd = (struct api_call_code*)cmd;
			guest_execute_code(ccmd->insns,
					   cmd_size - sizeof(struct api_call_header));
		} else if (call == SYZOS_API_IOCSR_WRITE) {
			if (cmd_size < sizeof(struct api_call_2))
				return;
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_iocsr_write(ccmd->args[0], ccmd->args[1]);
		} else if (call == SYZOS_API_CSRR) {
			if (cmd_size < sizeof(struct api_call_1))
				return;
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_csrr(cpu, (uint32)ccmd->arg);
		} else if (call == SYZOS_API_CSRW) {
			if (cmd_size < sizeof(struct api_call_2))
				return;
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_handle_csrw(cpu, (uint32)ccmd->args[0], ccmd->args[1]);
		} else if (call == SYZOS_API_MEMOP) {
			if (cmd_size < sizeof(struct api_call_5))
				return;
			struct api_call_5* ccmd = (struct api_call_5*)cmd;
			guest_handle_memop(cpu, ccmd);
		}
		addr += cmd_size;
		size -= cmd_size;
	}
	guest_uexit((uint64)-1);
}

// Perform a userspace exit that can be handled by the host.
// Host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO.
GUEST_CODE static noinline void guest_uexit(uint64 exit_code)
{
	volatile uint64* ptr = (volatile uint64*)LOONG64_ADDR_UEXIT;
	*ptr = exit_code;
}

// Host writes the instruction blob before KVM_RUN. Make it visible to
// instruction fetch before entering the blob and its fixed return instruction.
GUEST_CODE static noinline void guest_execute_code(uint32* insns, uint64 size)
{
	(void)size;
	sync_guest_insns();
	volatile void (*fn)() = (volatile void (*)())insns;
	fn();
}

GUEST_CODE static noinline void guest_iocsr_write(uint64 addr, uint64 value)
{
	// LoongArch syntax is iocsrwr.d value, address.
	asm volatile("iocsrwr.d %0, %1" : : "r"(value), "r"(addr) : "memory");
}

#define LOONG64_SYZOS_SCRATCH_SIZE 256
#define LOONG64_OPCODE_CSRRD 0x04000000
#define LOONG64_OPCODE_CSRWR 0x04000020
#define LOONG64_OPCODE_RET 0x4c000020
#define LOONG64_SYZOS_REG_A0 4
#define ENCODE_CSR_INSN(opcode, csr, rd) \
	((opcode) | ((((uint32)(csr)) & 0x3fff) << 10) | ((rd) & 0x1f))

GUEST_CODE static noinline void sync_guest_insns(void)
{
	asm volatile("dbar 0" ::: "memory");
	asm volatile("ibar 0" ::: "memory");
}

GUEST_CODE static noinline void guest_handle_csrr(uint64 cpu, uint32 csr)
{
	uint32* insns = (uint32*)(LOONG64_ADDR_SCRATCH_CODE +
				  cpu * LOONG64_SYZOS_SCRATCH_SIZE);
	insns[0] = ENCODE_CSR_INSN(LOONG64_OPCODE_CSRRD, csr, LOONG64_SYZOS_REG_A0);
	insns[1] = LOONG64_OPCODE_RET;
	sync_guest_insns();
	uint64 (*fn)() = (uint64 (*)())insns;
	(void)fn();
}

GUEST_CODE static noinline void guest_handle_csrw(uint64 cpu, uint32 csr, uint64 value)
{
	uint32* insns = (uint32*)(LOONG64_ADDR_SCRATCH_CODE +
				  cpu * LOONG64_SYZOS_SCRATCH_SIZE);
	insns[0] = ENCODE_CSR_INSN(LOONG64_OPCODE_CSRWR, csr, LOONG64_SYZOS_REG_A0);
	insns[1] = LOONG64_OPCODE_RET;
	sync_guest_insns();
	void (*fn)(uint64) = (void (*)(uint64))insns;
	fn(value);
}

#define LOONG64_SYZOS_MEMOP_WINDOW_SIZE 4096

// Execute a bounded guest memory operation. The syzlang producer selects an
// aligned address in the mapped stack window. Repeat the range checks here so
// malformed command streams cannot reach the later exception-recovery scope.
GUEST_CODE static noinline void guest_handle_memop(uint64 cpu, struct api_call_5* cmd)
{
	uint64 base = cmd->args[0];
	uint64 offset = cmd->args[1];
	uint64 value = cmd->args[2];
	uint64 len = cmd->args[3];
	uint64 op = cmd->args[4];
	if ((len != 1 && len != 2 && len != 4 && len != 8) ||
	    (op != 0 && op != 1))
		return;
	if (base != LOONG64_ADDR_STACK_BASE ||
	    offset > LOONG64_SYZOS_MEMOP_WINDOW_SIZE - sizeof(uint64) ||
	    offset % sizeof(uint64))
		return;
	if (offset > (uint64)-1 - base)
		return;
	uint64 addr = base + offset;
	if (len > (uint64)-1 - addr)
		return;

	asm volatile("dbar 0" ::: "memory");
	if (op == 1) {
		if (len == 1)
			*(volatile uint8*)addr = (uint8)value;
		else if (len == 2)
			*(volatile uint16*)addr = (uint16)value;
		else if (len == 4)
			*(volatile uint32*)addr = (uint32)value;
		else
			*(volatile uint64*)addr = value;
		asm volatile("dbar 0" ::: "memory");
		return;
	}

	uint64 result;
	if (len == 1)
		result = *(volatile uint8*)addr;
	else if (len == 2)
		result = *(volatile uint16*)addr;
	else if (len == 4)
		result = *(volatile uint32*)addr;
	else
		result = *(volatile uint64*)addr;
	asm volatile("dbar 0" ::: "memory");
	// KS0 is exposed through LoongArch KVM one-reg for host observation.
	guest_handle_csrw(cpu, 0x30, result);
}

#endif // EXECUTOR_COMMON_KVM_LOONG64_SYZOS_H
