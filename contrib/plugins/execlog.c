/*
 * Copyright (C) 2021, Alexandre Iooss <erdnaxe@crans.org>
 *
 * Log instruction execution with memory access and register changes
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

#define BUF_SIZE (512 * 1024 * 1024)

typedef struct {
  struct qemu_plugin_register *handle;
  GByteArray *last;
  GByteArray *new;
  const char *name;
} Register;

typedef struct LogRecord {
  uint64_t insn_count;
  char store;
  uint64_t address;
} LogRecord;

typedef struct CPU {
  /* Store last executed instruction on each vCPU as a GString */
  char *last_exec;
  char *buf_start;
  FILE *logfile;
  /* Ptr array of Register */
  GPtrArray *registers;
  LogRecord record;
} CPU;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static CPU *cpus;
static int cpu_len;

static GPtrArray *imatches;
static GArray *amatches;
static GPtrArray *rmatches;
static bool disas_assist;
static GMutex add_reg_name_lock;
static GPtrArray *all_reg_names;
static uint64_t insn_count;

static inline void buf_write(CPU *cpu, void *value, size_t len) {
  memcpy(cpu->last_exec, value, len);
  cpu->last_exec += len;
}

static inline void buf_write_char(CPU *cpu, char value) {
  *cpu->last_exec = value;
  ++cpu->last_exec;
}

static inline void buf_dump(CPU *cpu) {
  fwrite(cpu->buf_start, 1, cpu->last_exec - cpu->buf_start, cpu->logfile);
  cpu->last_exec = cpu->buf_start;
}

/**
 * Add memory read or write information to current instruction log
 */
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata) {

  if (!qemu_plugin_log_is_enabled()) {
    return;
  }

  CPU *c = cpus + cpu_index;
  /* Find vCPU in array */
  if (c->last_exec >= c->buf_start + BUF_SIZE - 500) {
    buf_dump(c);
  }
  /* Indicate type of memory access */
  if (qemu_plugin_mem_is_store(info)) {
    c->record.store = 1;
  } else {
    c->record.store = 0;
  }

  /* If full system emulation log physical address and device name */
  struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
  if (qemu_plugin_hwaddr_is_io(hwaddr)) {
    return;
  }
  GString *test = g_string_new(NULL);
  uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
  c->record.address = addr;
  buf_write(c, &c->record, sizeof(LogRecord));
}
// static void tb_exec(unsigned int cpu_index, void *udata) {
//   cpus[cpu_index].record.insn_count =
//       __atomic_fetch_add(&insn_count, (size_t)udata, __ATOMIC_RELAXED);
// }

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
  if (!qemu_plugin_log_is_enabled()) {
    return;
  }
  cpus[cpu_index].record.insn_count =
      __atomic_fetch_add(&insn_count, 1, __ATOMIC_SEQ_CST);
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  struct qemu_plugin_insn *insn;

  size_t n_insns = qemu_plugin_tb_n_insns(tb);
  // qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS,
  //                                      (void *)n_insns);
  for (size_t i = 0; i < n_insns; i++) {
    // uint64_t insn_addr;

    /*
     * `insn` is shared between translations in QEMU, copy needed data here.
     * `output` is never freed as it might be used multiple times during
     * the emulation lifetime.
     * We only consider the first 32 bits of the instruction, this may be
     * a limitation for CISC architectures.
     */
    insn = qemu_plugin_tb_get_insn(tb, i);
    // insn_addr = (uintptr_t) qemu_plugin_insn_haddr(insn);

    /* Register callback on memory read or write */
    qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS,
                                     QEMU_PLUGIN_MEM_RW, NULL);

    /* Register callback on instruction */
    qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                           QEMU_PLUGIN_CB_NO_REGS, NULL);
  }
}

static Register *init_vcpu_register(qemu_plugin_reg_descriptor *desc) {
  Register *reg = g_new0(Register, 1);
  g_autofree gchar *lower = g_utf8_strdown(desc->name, -1);
  int r;

  reg->handle = desc->handle;
  reg->name = g_intern_string(lower);
  reg->last = g_byte_array_new();
  reg->new = g_byte_array_new();

  /* read the initial value */
  r = qemu_plugin_read_register(reg->handle, reg->last);
  g_assert(r > 0);
  return reg;
}

/*
 * g_pattern_match_string has been deprecated in Glib since 2.70 and
 * will complain about it if you try to use it. Fortunately the
 * signature of both functions is the same making it easy to work
 * around.
 */
static inline gboolean g_pattern_spec_match_string_qemu(GPatternSpec *pspec,
                                                        const gchar *string) {
#if GLIB_CHECK_VERSION(2, 70, 0)
  return g_pattern_spec_match_string(pspec, string);
#else
  return g_pattern_match_string(pspec, string);
#endif
};
#define g_pattern_spec_match_string(p, s) g_pattern_spec_match_string_qemu(p, s)

static GPtrArray *registers_init(int vcpu_index) {
  g_autoptr(GPtrArray) registers = g_ptr_array_new();
  g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

  if (rmatches && reg_list->len) {
    /*
     * Go through each register in the complete list and
     * see if we want to track it.
     */
    for (int r = 0; r < reg_list->len; r++) {
      qemu_plugin_reg_descriptor *rd =
          &g_array_index(reg_list, qemu_plugin_reg_descriptor, r);
      for (int p = 0; p < rmatches->len; p++) {
        g_autoptr(GPatternSpec) pat = g_pattern_spec_new(rmatches->pdata[p]);
        g_autofree gchar *rd_lower = g_utf8_strdown(rd->name, -1);
        if (g_pattern_spec_match_string(pat, rd->name) ||
            g_pattern_spec_match_string(pat, rd_lower)) {
          Register *reg = init_vcpu_register(rd);
          g_ptr_array_add(registers, reg);

          /* we need a list of regnames at TB translation time */
          if (disas_assist) {
            g_mutex_lock(&add_reg_name_lock);
            if (!g_ptr_array_find(all_reg_names, reg->name, NULL)) {
              g_ptr_array_add(all_reg_names, (gpointer)reg->name);
            }
            g_mutex_unlock(&add_reg_name_lock);
          }
        }
      }
    }
  }

  return registers->len ? g_steal_pointer(&registers) : NULL;
}

/*
 * Initialise a new vcpu/thread with:
 *   - last_exec tracking data
 *   - list of tracked registers
 *   - initial value of registers
 *
 * As we could have multiple threads trying to do this we need to
 * serialise the expansion under a lock.
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
  CPU *c;
  char filename[32];
  snprintf(filename, sizeof(filename), "exec.log.%d", vcpu_index);
  c = cpus + vcpu_index;
  c->logfile = fopen(filename, "w");
  c->buf_start = malloc(BUF_SIZE); // 1MB
  c->last_exec = c->buf_start;
  c->registers = registers_init(vcpu_index);
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t id, void *p) {
  guint i;
  for (i = 0; i < cpu_len; i++) {
    CPU *c = cpus + i;
    buf_dump(c);
    fclose(c->logfile);
    free(c->buf_start);
  }
}

/* Add a match to the array of matches */
static void parse_insn_match(char *match) {
  if (!imatches) {
    imatches = g_ptr_array_new();
  }
  g_ptr_array_add(imatches, g_strdup(match));
}

static void parse_vaddr_match(char *match) {
  uint64_t v = g_ascii_strtoull(match, NULL, 16);

  if (!amatches) {
    amatches = g_array_new(false, true, sizeof(uint64_t));
  }
  g_array_append_val(amatches, v);
}

/*
 * We have to wait until vCPUs are started before we can check the
 * patterns find anything.
 */
static void add_regpat(char *regpat) {
  if (!rmatches) {
    rmatches = g_ptr_array_new();
  }
  g_ptr_array_add(rmatches, g_strdup(regpat));
}

/**
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
  /*
   * Initialize dynamic array to cache vCPU instruction. In user mode
   * we don't know the size before emulation.
   */
  cpus = malloc(info->system.max_vcpus * sizeof(CPU));
  cpu_len = info->system.max_vcpus;

  for (int i = 0; i < argc; i++) {
    char *opt = argv[i];
    g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
    if (g_strcmp0(tokens[0], "ifilter") == 0) {
      parse_insn_match(tokens[1]);
    } else if (g_strcmp0(tokens[0], "afilter") == 0) {
      parse_vaddr_match(tokens[1]);
    } else if (g_strcmp0(tokens[0], "reg") == 0) {
      add_regpat(tokens[1]);
    } else if (g_strcmp0(tokens[0], "rdisas") == 0) {
      if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &disas_assist)) {
        fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
        return -1;
      }
      all_reg_names = g_ptr_array_new();
    } else {
      fprintf(stderr, "option parsing failed: %s\n", opt);
      return -1;
    }
  }

  /* Register init, translation block and exit callbacks */
  qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
  qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

  return 0;
}
