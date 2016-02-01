/*
 * Memory access tracer
 *
 * Copyright (C) 2016 Du, Changbin <changbin.du@gamil.com>
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/fs.h>

#include "trace.h"
#include "trace_output.h"

#undef	pr_debug
#undef	pr_info
#define pr_debug pr_err
#define pr_info pr_err

struct mtrace_bp {
	struct list_head list;
	struct perf_event_attr attr;
	struct perf_event * __percpu *hbp;
};

static LIST_HEAD(mtrace_bps);
static DEFINE_SPINLOCK(mtrace_lock);
static struct trace_array *mtrace_array;

static char* hw_bp_type_string(int type)
{
	switch (type) {
	case HW_BREAKPOINT_R:
		return "R";
	case HW_BREAKPOINT_W:
		return "W";
	case HW_BREAKPOINT_RW:
		return "RW";
	case HW_BREAKPOINT_X:
		return "X";
	default:
		return "?";
	}
}

static void mtrace_add_bp(struct mtrace_bp *bp)
{
	list_add(&bp->list, &mtrace_bps);
}

static struct mtrace_bp * mtrace_find_bp(unsigned long addr)
{
	struct mtrace_bp *bp;

	list_for_each_entry(bp, &mtrace_bps, list) {
		if (bp->attr.bp_addr == addr)
			return bp;
	}
	return NULL;
}

static void mtrace_destroy_bp(struct mtrace_bp *bp)
{
	kfree(bp);
}

static void trace_mem_access(struct trace_array *tr, struct mtrace_bp *bp,
			struct perf_sample_data *data, u64 value)
{
	struct trace_event_call *call = &event_mem;
	struct ring_buffer *buffer = tr->trace_buffer.buffer;
	struct ring_buffer_event *event;
	struct trace_mem *entry;
	int pc = preempt_count();

	event = trace_buffer_lock_reserve(buffer, TRACE_MEM,
					  sizeof(*entry), 0, pc);
	if (!event) {
		pr_warn("mtrace: drop trace\n");
		return;
	}

	entry = ring_buffer_event_data(event);
	entry->addr = data->addr;
	entry->pid = data->tid_entry.pid;
	entry->ip = data->ip;
	entry->type = bp->attr.bp_type;
	entry->size = bp->attr.bp_len;
	entry->value = value;

	if (!call_filter_check_discard(call, entry, buffer, event))
		trace_buffer_unlock_commit(tr, buffer, event, 0, pc);
}

static void hbp_handler(struct perf_event *event,
			struct perf_sample_data *data,
			struct pt_regs *regs)
{
	struct mtrace_bp *bp;
	struct perf_event_header header;
	u64 value = 0;

	spin_lock(&mtrace_lock);
	bp = mtrace_find_bp(data->addr);
	if (!bp)
		goto done;

	pr_debug("%s: 0x%p\n", __func__, (void *)bp->attr.bp_addr);
	perf_prepare_sample(&header, data, event, regs);

	switch (bp->attr.bp_len) {
	case HW_BREAKPOINT_LEN_1:
		value = *(u8 *)data->addr;
		break;
	case HW_BREAKPOINT_LEN_2:
		value = *(u16 *)data->addr;
		break;
	case HW_BREAKPOINT_LEN_4:
		value = *(u32 *)data->addr;
		break;
	case HW_BREAKPOINT_LEN_8:
		value = *(u64 *)data->addr;
		break;
	default:
		pr_err("invalid bp len\n");
	}

	if (mtrace_array) {
		tracing_record_cmdline(current);
		trace_mem_access(mtrace_array, bp, data, value);
	} else
		pr_err("mtrace_array is null\n");
done:
	spin_unlock(&mtrace_lock);
}

static int mtrace_enable_bp(struct mtrace_bp *bp)
{
	struct perf_event * __percpu *hbp;
	int ret = 0;

	if (bp->hbp)
		return 0;

	hbp = register_wide_hw_breakpoint(&bp->attr, hbp_handler, bp);
	if (IS_ERR((void __force *)hbp)) {
		ret = PTR_ERR((void __force *)hbp);
		pr_err("bp for 0x%p registration failed %d\n",
			(void *)bp->attr.bp_addr, ret);
		return ret;
	}
	bp->hbp = hbp;

	pr_debug("hw bp for 0x%p installed\n",
		(void *)bp->attr.bp_addr);
	return 0;
}

static int mtrace_enable_all_bps(void)
{
	struct mtrace_bp *bp;
	int ret = 0;

	list_for_each_entry(bp, &mtrace_bps, list) {
		ret = mtrace_enable_bp(bp);
		if (ret)
			break;
	}
	return ret;
}

static void mtrace_disable_bp(struct mtrace_bp *bp)
{
	if (bp->hbp) {
		unregister_wide_hw_breakpoint(bp->hbp);
		bp->hbp = NULL;
	}
}

static void mtrace_disable_all_bps(void)
{
	struct mtrace_bp *bp;

	list_for_each_entry(bp, &mtrace_bps, list) {
		mtrace_disable_bp(bp);
	}
}

static void mtrace_bps_reset(void)
{
	struct mtrace_bp *bp, *tmp;

	list_for_each_entry_safe(bp, tmp, &mtrace_bps, list) {
		mtrace_disable_bp(bp);
		list_del(&bp->list);
		mtrace_destroy_bp(bp);
	}
}

static int mtrace_init(struct trace_array *tr)
{
	pr_info("%s\n", __func__);

	spin_lock(&mtrace_lock);
	mtrace_array = tr;
	mtrace_enable_all_bps();
	spin_unlock(&mtrace_lock);
	return 0;
}

static void mtrace_reset(struct trace_array *tr)
{
	pr_info("%s\n", __func__);

	spin_lock(&mtrace_lock);
	mtrace_disable_all_bps();
	mtrace_array = NULL;
	spin_unlock(&mtrace_lock);
}

static void mtrace_start(struct trace_array *tr)
{
	pr_info("%s\n", __func__);
	spin_lock(&mtrace_lock);
	mtrace_enable_all_bps();
	spin_unlock(&mtrace_lock);
}

static void mtrace_stop(struct trace_array *tr)
{
	pr_info("%s\n", __func__);
	spin_lock(&mtrace_lock);
	mtrace_disable_all_bps();
	mtrace_array = NULL;
	spin_unlock(&mtrace_lock);
}

static void mem_print_header(struct seq_file *s)
{
	seq_puts(s, "# ADDRESS             CPU       TASK-PID    TIMESTAMP"
		    "  TYPE value              FUNCTION\n"
		    "#  |                   |           | |         |        "
		    "|     |                   |\n");
}

static enum print_line_t mem_print_line(struct trace_iterator *iter)
{
	struct trace_seq *s = &iter->seq;
	struct trace_mem *field = NULL;
	unsigned long secs = ns2usecs(iter->ts);
	unsigned long usec_rem = do_div(secs, USEC_PER_SEC);
	char comm[TASK_COMM_LEN];

	if (iter->ent->type != TRACE_MEM)
		return TRACE_TYPE_HANDLED; /* ignore unknown entries */

	trace_assign_type(field, iter->ent);
	trace_find_cmdline(field->pid, comm);
	trace_seq_printf(s, "  0x%-16p [%03d] %9s-%-4d %5lu.%06lu  %-3s ",
			(void *)field->addr,
			iter->cpu,
			comm,
			field->pid,
			secs,
			usec_rem,
			hw_bp_type_string(field->type));

	switch (field->size) {
	case HW_BREAKPOINT_LEN_1:
		trace_seq_printf(s, "0x%02llx%14s ", field->value, "");
		break;
	case HW_BREAKPOINT_LEN_2:
		trace_seq_printf(s, "0x%04llx%12s ", field->value, "");
		break;
	case HW_BREAKPOINT_LEN_4:
		trace_seq_printf(s, "0x%08llx%8s ", field->value, "");
		break;
	case HW_BREAKPOINT_LEN_8:
		trace_seq_printf(s, "0x%016llx ", field->value);
		break;
	default:
		pr_err("invalid bp len\n");
		trace_seq_printf(s, "0x%-16s ", "???");
	}

	trace_seq_printf(s, "%-pF\n", (void*)field->ip);
	return trace_handle_return(s);
}

static struct tracer mem_tracer __read_mostly =
{
	.name		= "memory",
	.init		= mtrace_init,
	.reset		= mtrace_reset,
	.start		= mtrace_start,
	.stop		= mtrace_stop,
	.print_header	= mem_print_header,
	.print_line	= mem_print_line,
};

__init static int init_mtracer(void)
{
	int ret;

	ret = register_tracer(&mem_tracer);
	if(ret) {
		pr_warn("Warning: could not register mem-tracer\n");
		return ret;
	}

	return 0;
}
core_initcall(init_mtracer);

static void *addr_start(struct seq_file *m, loff_t *pos)
{
	spin_lock(&mtrace_lock);

	if (list_empty(&mtrace_bps) && (!*pos))
		return (void *) 1;

	return seq_list_start(&mtrace_bps, *pos);
}

static void *addr_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (v == (void *)1)
		return NULL;

	return seq_list_next(v, &mtrace_bps, pos);
}

static void addr_stop(struct seq_file *m, void *p)
{
	spin_unlock(&mtrace_lock);
}

static int addr_show(struct seq_file *m, void *v)
{
	struct mtrace_bp *bp = list_entry(v,
		struct mtrace_bp, list);
	char symname[KSYM_NAME_LEN];

	if (v == (void *)1) {
		seq_puts(m, "# echo 'addr size type' >> set_mtrace_address\n"
			    "# addr = hex number or symbol\n"
			    "# size = 1, 2, 4 or 8\n"
			    "# type = R, W or RW\n");
		return 0;
	}

	seq_printf(m, "0x%p	%llu	%s	%s",
		(void *)bp->attr.bp_addr,
		bp->attr.bp_len,
		hw_bp_type_string(bp->attr.bp_type),
		bp->hbp ? "enabled" : "disabled");

	if (!lookup_symbol_name(bp->attr.bp_addr, symname))
		seq_printf(m, "	%s\n", symname);

	return 0;
}

static const struct seq_operations mtrace_addr_sops = {
	.start	= addr_start,
	.next	= addr_next,
	.stop	= addr_stop,
	.show	= addr_show,
};

static int
mtrace_addr_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	if ((file->f_mode & FMODE_WRITE) && (file->f_flags & O_TRUNC))
		mtrace_bps_reset();

	if (file->f_mode & FMODE_READ)
		ret = seq_open(file, &mtrace_addr_sops);

	return ret;
}

static int parse_line(char *line, unsigned long *addr, int *size, int *type)
{
	char symbol[KSYM_NAME_LEN], stype[3];
	unsigned long _addr;
	int _size, _type;

	if (strlen(line) < 2)
		return -EINVAL;

	if (strncmp(line, "0x", 2)) {
		/* lookup the symbol */
		char fmt[20];
		sprintf(fmt, "%%%lus%%d%%2s", sizeof(symbol));
		if (sscanf(line, fmt, symbol, &_size, stype) != 3)
			return -EINVAL;
		_addr = kallsyms_lookup_name(symbol);
		if (!_addr) {
			pr_err("mtrace: symbol %s not found\n", symbol);
			return -EINVAL;
		}
	} else {
		/* parse hex address */
		if (sscanf(line, "%lx%d%2s", &_addr, &_size, stype) != 3)
			return -EINVAL;
	}

	if (_size != HW_BREAKPOINT_LEN_1 && _size != HW_BREAKPOINT_LEN_2 &&
	    _size != HW_BREAKPOINT_LEN_4 && _size != HW_BREAKPOINT_LEN_8) {
		pr_err("mtrace: only support size 1/2/4/8\n");
		return -EINVAL;
	}

	if (!strcasecmp(stype, "R"))
		_type = HW_BREAKPOINT_R;
	else if (!strcasecmp(stype, "W"))
		_type = HW_BREAKPOINT_W;
	else if (!strcasecmp(stype, "RW"))
		_type = HW_BREAKPOINT_RW;
	else {
		pr_err("mtrace: invalid bp type '%s'\n", stype);
		return -EINVAL;
	}

	*addr = _addr;
	*size = _size;
	*type = _type;
	return 0;
}

static int is_kernel(unsigned long addr)
{
	if (addr >= (unsigned long)_stext && addr <= (unsigned long)_end)
		return 1;
	return in_gate_area_no_mm(addr);
}

static ssize_t
mtrace_addr_write(struct file *filp, const char __user *ubuf,
		   size_t cnt, loff_t *ppos)
{
	struct mtrace_bp *bp;
	char buf[KSYM_NAME_LEN + 20], *tmp;
	unsigned long addr;
	int size, type;

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;
	tmp = strstrip(buf);

	if (parse_line(tmp, &addr, &size, &type))
		return -EINVAL;

	if (!is_kernel(addr)) {
		pr_err("mtrace: only support kernel space\n");
		return -EINVAL;
	}

	if (mtrace_find_bp(addr)) {
		pr_info("mtrace: bp for 0x%p already exist\n", (void *)addr);
		return cnt;
	}

	bp = kmalloc(sizeof(*bp), GFP_KERNEL);
	if (!bp)
		return -ENOMEM;

	hw_breakpoint_init(&bp->attr);
	bp->attr.bp_addr = addr;
	bp->attr.bp_len = size;
	bp->attr.bp_type = type;
	bp->attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
			       PERF_SAMPLE_TIME | PERF_SAMPLE_CPU;
	bp->hbp = NULL;

	spin_lock(&mtrace_lock);
	mtrace_add_bp(bp);
	if (mtrace_array)
		mtrace_enable_bp(bp);
	spin_unlock(&mtrace_lock);

	return cnt;
}

static int
mtrace_addr_release(struct inode *inode, struct file *file)
{
	if (file->f_mode & FMODE_READ)
		seq_release(inode, file);

	return 0;
}

static const struct file_operations mtrace_addr_fops = {
	.open		= mtrace_addr_open,
	.write		= mtrace_addr_write,
	.read		= seq_read,
	.llseek		= tracing_lseek,
	.release	= mtrace_addr_release,
};

static __init int mtrace_init_tracefs(void)
{
	struct dentry *d_tracer;

	d_tracer = tracing_init_dentry();
	if (IS_ERR(d_tracer))
		return 0;

	trace_create_file("set_mtrace_addr", 0644, d_tracer,
			    NULL, &mtrace_addr_fops);

	return 0;
}
fs_initcall(mtrace_init_tracefs);
