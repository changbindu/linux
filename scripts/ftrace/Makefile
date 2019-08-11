# SPDX-License-Identifier: GPL-2.0

hostprogs-$(BUILD_C_RECORDMCOUNT) := recordmcount

hostprogs-$(CONFIG_FTRACE_FUNC_PROTOTYPE) += funcprototype
HOSTLDLIBS_funcprototype += -lelf
HOSTLDLIBS_funcprototype += -ldw

always         := $(hostprogs-y)
