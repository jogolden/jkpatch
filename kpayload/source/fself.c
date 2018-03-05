/* golden */
/* 1/2/2018 */

#include "fself.h"

int sceSblAuthMgrGetSelfAuthInfoFake(struct self_context *ctx, struct self_auth_info *info) {
	struct self_header *hdr;
	struct self_fake_auth_info *fake_info;

	if (ctx->format == SELF_FORMAT_SELF) {
		hdr = (struct self_header *)ctx->header;
		fake_info = (struct self_fake_auth_info *)(ctx->header + hdr->header_size + hdr->meta_size - 0x100);
		if (fake_info->size == sizeof(fake_info->info)) {
			memcpy(info, &fake_info->info, sizeof(*info));
			return 0;
		}

		return -37;
	} else {
		return -35;
	}
}

int is_fake_self(struct self_context *ctx) {
	struct self_ex_info *ex_info;

	if (ctx && ctx->format == SELF_FORMAT_SELF) {
		if (sceSblAuthMgrGetSelfInfo(ctx, &ex_info)) {
			return 0;
		}

		return ex_info->ptype == SELF_PTYPE_FAKE;
	}

	return 0;
}

int sceSblAuthMgrGetElfHeader(struct self_context *ctx, struct Elf64_Ehdr **ehdr) {
	struct self_header *self_hdr;
	struct Elf64_Ehdr *elf_hdr;
	size_t pdata_size;

	if (ctx->format == SELF_FORMAT_ELF) {
		elf_hdr = (struct Elf64_Ehdr*)ctx->header;
		if (ehdr) {
			*ehdr = elf_hdr;
		}

		return 0;
	} else if (ctx->format == SELF_FORMAT_SELF) {
		self_hdr = (struct self_header*)ctx->header;
		pdata_size = self_hdr->header_size - sizeof(struct self_entry) * self_hdr->num_entries - sizeof(struct self_header);
		if (pdata_size >= sizeof(struct Elf64_Ehdr) && (pdata_size & 0x0F) == 0) {
			elf_hdr = (struct Elf64_Ehdr*)((uint8_t*)self_hdr + sizeof(struct self_header) + sizeof(struct self_entry) * self_hdr->num_entries);
			if (ehdr) {
				*ehdr = elf_hdr;
			}

			return 0;
		}

		return -37;
	}

	return -35;
}

int build_self_auth_info_fake(struct self_context *ctx, struct self_auth_info *parent_auth_info, struct self_auth_info *auth_info) {
	struct self_auth_info fake_auth_info;
	struct self_ex_info *ex_info = NULL;
	struct Elf64_Ehdr *ehdr = NULL;
	int result;

	if (!ctx || !parent_auth_info || !auth_info) {
		result = EINVAL;
		goto error;
	}

	if (!is_fake_self(ctx)) {
		result = EINVAL;
		goto error;
	}

	result = sceSblAuthMgrGetSelfInfo(ctx, &ex_info);
	if (result) {
		goto error;
	}

	result = sceSblAuthMgrGetElfHeader(ctx, &ehdr);
	if (result) {
		goto error;
	}

	if (!ehdr) {
		result = ESRCH;
		goto error;
	}

	result = sceSblAuthMgrGetSelfAuthInfoFake(ctx, &fake_auth_info);
	if (result) {
		switch (ehdr->e_type) {
		case ELF_ET_EXEC:
		case ELF_ET_SCE_EXEC:
		case ELF_ET_SCE_EXEC_ASLR: {
			memcpy(&fake_auth_info, s_auth_info_for_exec, sizeof(fake_auth_info));
			result = 0;
			break;
		}
		case ELF_ET_SCE_DYNAMIC: {
			memcpy(&fake_auth_info, s_auth_info_for_dynlib, sizeof(fake_auth_info));
			result = 0;
			break;
		}
		default: {
			result = ENOTSUP;
			goto error;
		}
		}

		fake_auth_info.paid = ex_info->paid;
		// TODO: overwrite low bits of PAID with title id number
	}

	if (auth_info) {
		memcpy(auth_info, &fake_auth_info, sizeof(*auth_info));
	}

error:
	return result;
}

int hook_sceSblAuthMgrIsLoadable2(struct self_context *ctx, struct self_auth_info *old_auth_info, int path_id, struct self_auth_info *new_auth_info) {
	if (ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx)) {
		return build_self_auth_info_fake(ctx, old_auth_info, new_auth_info);
	} else {
		return sceSblAuthMgrIsLoadable2(ctx, old_auth_info, path_id, new_auth_info);
	}
}

int auth_self_header(struct self_context *ctx) {
	struct self_header *hdr;
	unsigned int old_total_header_size, new_total_header_size;
	int old_format;
	uint8_t* tmp;
	int is_unsigned;
	int result;

	is_unsigned = ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx);
	if (is_unsigned) {
		old_format = ctx->format;
		old_total_header_size = ctx->total_header_size;

		/* take a header from mini-syscore.elf */
		hdr = (struct self_header *)mini_syscore_self_binary;

		new_total_header_size = hdr->header_size + hdr->meta_size;

		tmp = (uint8_t *)alloc(new_total_header_size);
		if (!tmp) {
			result = ENOMEM;
			goto error;
		}

		/* temporarily swap an our header with a header from a real SELF file */
		memcpy(tmp, ctx->header, new_total_header_size);
		memcpy(ctx->header, hdr, new_total_header_size);

		/* it's now SELF, not ELF or whatever... */
		ctx->format = SELF_FORMAT_SELF;
		ctx->total_header_size = new_total_header_size;

		/* call the original method using a real SELF file */
		result = sceSblAuthMgrVerifyHeader(ctx);

		/* restore everything we did before */
		memcpy(ctx->header, tmp, new_total_header_size);
		ctx->format = old_format;
		ctx->total_header_size = old_total_header_size;

		dealloc(tmp);
	} else {
		result = sceSblAuthMgrVerifyHeader(ctx);
	}

error:
	return result;
}

int hook_sceSblAuthMgrVerifyHeader(struct self_context *ctx) {
	void *dummy;
	sceSblAuthMgrSmStart(&dummy);
	return auth_self_header(ctx);
}

int hook_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t *request, void *response) {
	/* getting a stack frame of a parent function */
	uint8_t *frame = (uint8_t *)__builtin_frame_address(1);

	/* finding a pointer to a context's structure */
	struct self_context *ctx = *(struct self_context **)(frame - 0x100);
	int is_unsigned = ctx && is_fake_self(ctx);
	if (is_unsigned) {
		*(int *)(response + 0x04) = 0; /* setting error field to zero, thus we have no errors */
		return 0;
	}

	return sceSblServiceMailbox(service_id, request, response);
}

int hook_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t *request, void *response) {
	struct self_context *ctx;
	register struct self_context *ctx_reg __asm__("r14"); // cool fix?

	vm_offset_t segment_data_gpu_va = *(unsigned long *)(request + 0x08);
	vm_offset_t cur_data_gpu_va = *(unsigned long *)(request + 0x50);
	vm_offset_t cur_data2_gpu_va = *(unsigned long *)(request + 0x58);
	unsigned int data_offset = *(unsigned int *)(request + 0x44);
	unsigned int data_size = *(unsigned int *)(request + 0x48);
	vm_offset_t segment_data_cpu_va, cur_data_cpu_va, cur_data2_cpu_va;
	unsigned int size1;

	ctx = ctx_reg;

	int is_unsigned = ctx && (ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx));
	int result;

	if (is_unsigned) {
		/* looking into lists of GPU's mapped memory regions */
		segment_data_cpu_va = sceSblDriverGpuVaToCpuVa(segment_data_gpu_va, NULL);
		cur_data_cpu_va = sceSblDriverGpuVaToCpuVa(cur_data_gpu_va, NULL);
		cur_data2_cpu_va = cur_data2_gpu_va ? sceSblDriverGpuVaToCpuVa(cur_data2_gpu_va, NULL) : 0;

		if (segment_data_cpu_va && cur_data_cpu_va) {
			if (cur_data2_gpu_va && cur_data2_gpu_va != cur_data_gpu_va && data_offset > 0) {
				/* data spans two consecutive memory's pages, so we need to copy twice */
				size1 = PAGE_SIZE - data_offset;
				memcpy((char *)segment_data_cpu_va, (char *)cur_data_cpu_va + data_offset, size1);
				memcpy((char *)segment_data_cpu_va + size1, (char *)cur_data2_cpu_va, data_size - size1);
			} else {
				memcpy((char *)segment_data_cpu_va, (char *)cur_data_cpu_va + data_offset, data_size);
			}
		}

		*(int *)(request + 0x04) = 0; /* setting error field to zero, thus we have no errors */
		result = 0;
	} else {
		result = sceSblServiceMailbox(service_id, request, response);
	}

	return result;
}

void install_fself_hooks() {
	// disable write protect
	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	uint64_t kernbase = getkernbase();

	// hook_sceSblAuthMgrIsLoadable2
	write_jmp(kernbase + 0x60C610, (uint64_t)hook_sceSblAuthMgrIsLoadable2);
	KCALL_REL32(kernbase, 0x61F24F, 0x60C610);

	// hook_sceSblAuthMgrVerifyHeader
	write_jmp(kernbase + 0x61A861, (uint64_t)hook_sceSblAuthMgrVerifyHeader);
	KCALL_REL32(kernbase, 0x61F976, 0x61A861);
	KCALL_REL32(kernbase, 0x620599, 0x61A861);

	// hook_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox
	write_jmp(kernbase + 0x622540, (uint64_t)hook_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox);
	KCALL_REL32(kernbase, 0x6238BA, 0x622540);

	// hook_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox
	write_jmp(kernbase + 0x626791, (uint64_t)hook_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox);
	KCALL_REL32(kernbase, 0x6244E1, 0x626791);

	// restore CR0
	__writecr0(CR0);

	uprintf("[jkpatch] installed fself hooks!");
}