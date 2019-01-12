// SPDX-License-Identifier: GPL-2.0-only
/*
 * funcprototype.c: generate function prototypes of the locations of calls to 'mcount'
 * so that ftrace can record function parameters and return value.
 *
 * Copyright 2019 Changbin Du <changbin.du@gmail.com>.  All rights reserved.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <argp.h>
#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

struct func_param {
	char *name;
	uint8_t type;
	u_int8_t loc[2]; /* Location expression, loc[0] is opcode */
};

struct func_prototype {
	struct func_prototype *next;
	bool skip;

	char *name;
	uint8_t ret_type;
	uint8_t nr_param;
	struct func_param *params;
};

#define MK_TYPE(signed, size)	(((!!signed) << 7) | size)

static bool is_64bit_obj;
static struct func_prototype *func_prototype_list;


static struct func_prototype *func_prototype_list_add_new(const char *name)
{
	struct func_prototype *proto;

	proto = malloc(sizeof(*proto));
	if (!proto)
		errx(1, "no memory");
	memset(proto, 0, sizeof(*proto));

	proto->name = strdup(name);
	if (!proto->name)
		errx(1, "no memory");

	if (!func_prototype_list) {
		proto->next = NULL;
		func_prototype_list = proto;
	} else {
		proto->next = func_prototype_list->next;
		func_prototype_list->next = proto;
	}

	return proto;
}

static struct func_prototype *func_prototype_list_search(const char *name)
{
	struct func_prototype *proto;

	for (proto = func_prototype_list; proto != NULL; proto = proto->next) {
		if (!strcmp(proto->name, name))
			return proto;
	};
	return NULL;
}

static void func_prototype_list_dumpnames(void)
{
	struct func_prototype *proto;

	for (proto = func_prototype_list; proto != NULL; proto = proto->next)
		printf("%s\n", proto->name);
}

static void func_prototype_list_destroy(void)
{
	struct func_prototype *proto;
	int i;

	while (func_prototype_list) {
		proto = func_prototype_list;
		func_prototype_list = func_prototype_list->next;

		free(proto->name);
		if (proto->params) {
			for (i = 0; i < proto->nr_param; i++)
				free(proto->params[i].name);
			free(proto->params);
		}
		free(proto);
	}
}

static bool is_mcount(char *name)
{
	return !strcmp(name, "__fentry__") ||
	       !strcmp(name, "_mcount") ||
	       !strcmp(name, "mcount");
}

static void check_elf(Elf *elf)
{
	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr;

	ehdr = gelf_getehdr (elf, &ehdr_mem);
	if (!ehdr)
		errx(1, "cannot read ELF header");

	is_64bit_obj = gelf_getclass(elf) == ELFCLASS64;

	switch (ehdr->e_machine) {
	case EM_386:
	case EM_X86_64:
		break;
	default:
		errx(1, "unsupported arch %d", ehdr->e_machine);
	}
}

/**
 * Search the symbole table to get the entry which matches @scn and @offset
 * from relocation talbe.
 */
static char *search_mcount_caller(Elf *elf, GElf_Shdr *symshdr,
				  Elf_Data *symdata, int scn, int offset)
{
	int ndx;
	char *caller;

	for (ndx = 0; ndx < symshdr->sh_size / symshdr->sh_entsize; ++ndx) {
		GElf_Sym sym;
		gelf_getsym(symdata, ndx, &sym);

		/* TODO: add local symobl support. */
		if (GELF_ST_BIND (sym.st_info) == STB_GLOBAL &&
		    scn == sym.st_shndx && (offset >= sym.st_value) &&
		    (offset < sym.st_value + sym.st_size)) {
			caller = elf_strptr(elf, symshdr->sh_link, sym.st_name);
			return caller;
		}
	}

	return NULL;
}

/* Get all functions that call to mcount. */
static void get_mcount_callers(const char *elf_file)
{
	Elf *elf;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	int fd;
	int ndx;

	fd = open(elf_file, O_RDONLY);
	if (fd < 0)
		errx(1, "can not open %s", elf_file);

	elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_READ, NULL);

	check_elf(elf);

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		gelf_getshdr(scn, &shdr);

		if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA) {
			Elf_Data *data = elf_getdata(scn, NULL);
			Elf_Scn *symscn = elf_getscn(elf, shdr.sh_link);
			Elf_Data *symdata = elf_getdata(symscn, NULL);
			GElf_Shdr symshdr_mem;
			GElf_Shdr *symshdr = gelf_getshdr(symscn, &symshdr_mem);

			for (ndx = 0; ndx < shdr.sh_size / shdr.sh_entsize;
			     ++ndx) {
				unsigned long sym_index;
				unsigned long offset;
				GElf_Sym sym;
				char *symname;

				if (shdr.sh_type == SHT_REL) {
					GElf_Rel rel_mem;
					GElf_Rel *rel = gelf_getrel(data, ndx,
								    &rel_mem);
					sym_index = GELF_R_SYM(rel->r_info);
					offset = rel->r_offset;
				} else {
					GElf_Rela rela_mem;
					GElf_Rela *rela = gelf_getrela(
						data, ndx, &rela_mem);
					sym_index = GELF_R_SYM(rela->r_info);
					offset = rela->r_offset;
				}

				gelf_getsym(symdata, sym_index, &sym);
				symname = elf_strptr(elf, symshdr->sh_link,
						     sym.st_name);

				if (is_mcount(symname)) {
					const char *caller;
					caller = search_mcount_caller(
							elf, symshdr, symdata,
							shdr.sh_info, offset);
					/* Local symbol is not supported so far. */
					if (caller)
						func_prototype_list_add_new(caller);
				}
			}
		}
	}

	elf_end(elf);
	close(fd);
}

/*
 * Get a variable size and sign info.
 * TODO: Determine the expected display format. (e.g. size_t for "%lu").
 */
static void die_type_sign_bytes(Dwarf_Die *die, bool *is_signed, int *bytes)
{
	Dwarf_Attribute attr;
	Dwarf_Die type;
	int ret;

	*bytes = 0;
	*is_signed = false;

	ret = dwarf_peel_type(dwarf_formref_die(
			dwarf_attr_integrate(die, DW_AT_type, &attr), &type),
			&type);
	if (ret == 0) {
		Dwarf_Word val;

		ret = dwarf_formudata(dwarf_attr(&type, DW_AT_encoding,
					&attr), &val);
		if (ret == 0)
			*is_signed = (val == DW_ATE_signed) ||
				     (val == DW_ATE_signed_char);

		if (dwarf_aggregate_size(&type, &val) == 0)
			*bytes = val;
	}
}

static int get_func_nr_params(Dwarf_Die *funcdie)
{
	Dwarf_Die child;
	int count = 0;

	if (dwarf_child(funcdie, &child) == 0) {
		do {
			if (dwarf_tag(&child) == DW_TAG_formal_parameter)
				count++;
		} while (dwarf_siblingof(&child, &child) == 0);
	}

	return count;
}

static int get_loc_expr(const char *fname, Dwarf_Op *loc, uint8_t expr[2])
{
	int ret = 0;

	switch (loc[0].atom) {
	case DW_OP_reg0 ... DW_OP_reg31:
		expr[0] = loc[0].atom;
		expr[1] = 0;
		break;
	case DW_OP_fbreg:
		/*
		 * Very few functions have number great than 0xff. We skip these
		 * functions to keep protrotype data as small as possilbe.
		 */
		if (loc[0].number > 0xff) {
			warnx("%s: loc fbreg offset %lu too large",
			      fname, loc[0].number);
			ret = -1;
		} else {
			expr[0] = loc[0].atom;
			expr[1] = loc[0].number;
		}
		break;
	case DW_OP_breg0 ... DW_OP_breg31:
		if (loc[0].number > 0xff) {
			warnx("%s: loc bregx offset %lu too large",
			      fname, loc[0].number);
			ret = -1;
		} else {
			expr[0] = loc[0].atom;
			expr[1] = loc[0].number;
		}
		break;
	default:
		warnx("%s: unsupported loc operation 0x%x",
		      fname, loc[0].atom);
		ret = -1;
	};

	return ret;
}

static int handle_function(Dwarf_Die *funcdie, void *arg)
{
	const char *name = dwarf_diename(funcdie);
	Dwarf_Addr func_addr;
	Dwarf_Die child;
	struct func_prototype *proto;
	int nr_params;
	int sz, n = 0;

	if (!dwarf_hasattr(funcdie, DW_AT_low_pc))
		return 0;

	/* Such symbol is a local function generated by GCC ipa-fnsplit. */
	if (!dwarf_hasattr(funcdie, DW_AT_name))
		return 0;

	/* check whether it is a mcount caller. */
	proto = func_prototype_list_search(name);
	if (!proto)
		return 0;

	nr_params = get_func_nr_params(funcdie);
	sz = sizeof(proto->params[0]) * nr_params;
	proto->params = malloc(sz);
	if (!proto->params)
		errx(1, "no memory");

	memset(proto->params, 0, sz);

	dwarf_lowpc(funcdie, &func_addr);

	/* get function return type */
	if (dwarf_hasattr(funcdie, DW_AT_type)) {
		bool is_signed;
		int bytes;
		die_type_sign_bytes(funcdie, &is_signed, &bytes);
		proto->ret_type = MK_TYPE(is_signed, bytes);
	} else
		proto->ret_type = 0;

	/* process function parameters. */
	if (dwarf_child(funcdie, &child) == 0) {
		do {
			if (dwarf_tag(&child) == DW_TAG_formal_parameter) {
				Dwarf_Attribute locattr;
				Dwarf_Op *loc;
				size_t nloc = 0;
				bool is_signed;
				int bytes;

				die_type_sign_bytes(&child, &is_signed, &bytes);
				proto->params[n].name = strdup(dwarf_diename(&child));
				proto->params[n].type = MK_TYPE(is_signed, bytes);

				if (!dwarf_hasattr(&child, DW_AT_location))
					errx(1, "%s: no location attr", name);

				dwarf_attr(&child, DW_AT_location, &locattr);
				if (dwarf_getlocation(&locattr, &loc, &nloc) < 0) {
					Dwarf_Addr base, begin, end;
					if (dwarf_getlocations(
							&locattr, 0, &base,
							&begin, &end, &loc,
							&nloc) <= 0)
						errx(1, "%s: no param loc info",
						     name);
				}
				if (get_loc_expr(name, loc, proto->params[n].loc)) {
					/* skip this function. */
					proto->skip = true;
					return 0;
				}

				n++;
			};
		} while (dwarf_siblingof(&child, &child) == 0);
	}

	proto->nr_param = n;
	return 0;
}

/* Iterate each DW_TAG_subprogram DIE to get their prototype info. */
static void dwarf_get_prototypes(const char *elf_file)
{
	Dwfl *dwfl = NULL;
	Dwarf_Die *cu = NULL;
	Dwarf_Addr dwbias;
	static const Dwfl_Callbacks offline_callbacks =	{
		.find_debuginfo = dwfl_standard_find_debuginfo,
		.section_address = dwfl_offline_section_address,
	};

	dwfl = dwfl_begin(&offline_callbacks);
	if (dwfl == NULL)
	      errx(1, "dwfl fail");

	if (dwfl_report_offline(dwfl, "", elf_file, -1) == NULL)
		errx(1, "dwfl report fail");

	int result = dwfl_report_end(dwfl, NULL, NULL);
	assert (result == 0);

	 while ((cu = dwfl_nextcu(dwfl, cu, &dwbias)) != NULL)
		dwarf_getfuncs(cu, &handle_function, NULL, 0);
}

static void print_prototypes_assembly(void) {
	struct func_prototype *proto;
	int i;

	if (!func_prototype_list)
		return;

	printf("	.section __funcprotostr, \"a\"\n");
	for (proto = func_prototype_list; proto != NULL; proto = proto->next) {
		if (proto->skip)
			continue;
		for (i = 0; i < proto->nr_param; i++) {
			printf(".P_%s_%d:\n", proto->name, i);
			printf("	.string \"%s\"\n", proto->params[i].name);
		}
	};

	printf("\n	.section __funcproto,  \"a\"\n");
	for (proto = func_prototype_list; proto != NULL; proto = proto->next) {
		if (proto->skip)
			continue;
		if (is_64bit_obj)
			printf("	.quad %s\n", proto->name);
		else
			printf("	.long %s\n", proto->name);
		printf("	.byte 0x%x\n", proto->ret_type);
		printf("	.byte 0x%x\n", proto->nr_param);
		for (i = 0; i < proto->nr_param; i++) {
			if (is_64bit_obj)
				printf("	.quad .P_%s_%d\n", proto->name, i);
			else
				printf("	.long .P_%s_%d\n", proto->name, i);
			printf("	.byte 0x%x\n", proto->params[i].type);
			printf("	.byte 0x%x\n", proto->params[i].loc[0]);
			printf("	.byte 0x%x\n", proto->params[i].loc[1]);
		}
		printf("\n");
	};
}

/* Program documentation. */
static char doc[] =
	"funcprototype -- a program to generate mcount caller prototypes";

/* A description of the arguments we accept. */
static char args_doc[] = "elf-file";

/* The options we understand. */
static struct argp_option options[] = { { "mcount-callers", 'm', 0, 0,
					  "show mcount callers only" },
					{ 0 } };

struct arguments {
	char *elf_file;
	int show_callers_only;
};

/* Parse options. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
	case 'm':
		arguments->show_callers_only = 1;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num > 2) {
			/* Too many arguments. */
			argp_usage(state);
		}
		arguments->elf_file = arg;
		break;
	case ARGP_KEY_END:
		if (state->arg_num < 1)
			/* Not enough arguments. */
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char *argv[])
{
	struct arguments arguments;

	arguments.show_callers_only = 0;
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	get_mcount_callers(arguments.elf_file);

	if (arguments.show_callers_only) {
		func_prototype_list_dumpnames();
		goto free;
	}

	dwarf_get_prototypes(arguments.elf_file);
	print_prototypes_assembly();

free:
	func_prototype_list_destroy();
	return 0;
}
