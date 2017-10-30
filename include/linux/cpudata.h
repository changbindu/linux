#ifndef __LINUX_CPUDATA_H
#define __LINUX_CPUDATA_H

#include <linux/cpumask.h>
#include <linux/slab.h>

#if defined(CONFIG_STATIC_CPU_DATA) || NR_CPUS <= 8
#define CPU_DATA_PROT(type, name)	__typeof__(type) name[NR_CPUS]

#define cpu_data_size(name)		(sizeof(name))
#define cpu_data_alloc(name, gfp_flags)	true
#define cpu_data_free(name)		do {} while (0)

#define cpu_data_alloc_bootmem(name)	true
#define cpu_data_free_bootmem(name)	do {} while (0)

#define cpu_data_get(cpu, name)		(BUG_ON(cpu >= NR_CPUS), name[cpu])
#else
#define CPU_DATA_PROT(type, name)	__typeof__(type) *name

#define cpu_data_size(name)		(sizeof(name[0]) * nr_cpu_ids)
#define cpu_data_alloc(name, gfp_flags) \
	(name = kzalloc(cpu_data_size(name), gfp_flags), !!name)
#define cpu_data_free(name)		kfree(name)

#define cpu_data_alloc_bootmem(name) \
	(name = memblock_virt_alloc(cpu_data_size(name), 0), !!name)
#define cpu_data_free_bootmem(name) \
	memblock_free_early(__pa(name), cpu_data_size(name))

#define cpu_data_get(cpu, name)		(BUG_ON(cpu >= nr_cpu_ids), name[cpu])
#endif

#endif /* __LINUX_CPUDATA_H */
