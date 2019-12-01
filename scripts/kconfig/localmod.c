#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include<sys/types.h>
#include<sys/dir.h>
#include<dirent.h>
#include<fcntl.h>
#include<unistd.h>
#include <regex.h>

#include "list.h"
#include "expr.h"
#include "lkc_proto.h"

struct mod_config {
    struct list_head node;
    char *conf_name;
    char *mod_name;
    bool loaded;
};

static LIST_HEAD(module_config_list);
static char *src_arch;

static const char * regexstr = "obj-\\$\\(CONFIG_([A-Z_]*)\\)[\\t\\ ][\\+:]?=[\\t\\ ]([a-zA-Z0-9\\ \\t/\\.-_]*)";
static regex_t regex_compiled;

static void add_module_config(char *conf_name, char *mod_name)
{
    struct mod_config *mod;

    printf("CONFIG_%s - %s\n", conf_name, mod_name);

    mod = malloc(sizeof(*mod));
    if (!mod) {
        perror("no memory\n");
        exit(-1);
    }

    mod->conf_name = strdup(conf_name);
    mod->mod_name = strdup(mod_name);
    mod->loaded = false;
    list_add_tail(&mod->node, &module_config_list);
}

static void parse_line(char *line)
{
    
    regmatch_t groups[3];
    char *mod_name;
    size_t len;
    int err;

    err = regexec(&regex_compiled, line, 3, groups, 0);
    if (err) {
        return;
    }

    if (groups[1].rm_so == (size_t)-1 || groups[2].rm_so == (size_t)-1) {
        return;
    }

    line[groups[1].rm_so - 1] = '\0';
    line[groups[1].rm_eo] = '\0';
    line[groups[2].rm_so - 1] = '\0';
    line[groups[2].rm_eo] = '\0';

    mod_name = strtok (&line[groups[2].rm_so]," \t");
    while (mod_name != NULL) {
        len = strlen(mod_name);
        if (len > 2 && mod_name[len-2] == '.' && mod_name[len-1] == 'o') {
            mod_name[len-2] = '\0';
            add_module_config(&line[groups[1].rm_so], mod_name);
        }
        mod_name = strtok(NULL, " \t");
    }
}

static char *rtrim(char *s)
{
    char* p = s + strlen(s);

    while(isspace(*--p));
    *(p+1) = '\0';

    return s;
}

static ssize_t readline(FILE *stream, char **line)
{
    char *ptr = NULL;
    char *buf = NULL;
    size_t cur_len = 0, len;
    ssize_t nread;

    while (true) {
        nread = getline(&buf, &len, stream);
        if (nread == -1) {
            free(ptr);
            return -1;
        }

        ptr = realloc(ptr, cur_len + len);
        if (ptr == NULL) {
            free(buf);
            return -1;
        }

        sprintf(ptr + cur_len, " %s", buf);
        cur_len += len + 1;
        rtrim(ptr);

        if (ptr[strlen(ptr)-1] != '\\')
            break;
    }

    free(buf);
    *line = ptr;
    return cur_len;
}

static void parse_makefile(char *path)
{
    FILE *stream;
    char *line = NULL;
    ssize_t nread;

    stream = fopen(path, "r");
    if (stream == NULL) {
        perror("fopen");
        return;
    }

    while ((nread = readline(stream, &line)) != -1) {
        parse_line(line);
        free(line);
    }

    fclose(stream);
}

static int search_directory(char *dirname, int level)
{
    DIR *dir;
    struct dirent *dirp;
    char d_path[PATH_MAX];
    int ret;

    dir=opendir(dirname);
    if (!dir) {
	    fprintf(stderr, "cannot open %s\n", dirname);
	    return -1;
    }

    while((dirp=readdir(dir)) != NULL) {
        if(dirp->d_type == DT_DIR) {
            if(strcmp(dirp->d_name, ".")==0 || strcmp(dirp->d_name, "..")==0)
                continue;

            if (level == 0 && strcmp(dirp->d_name, "arch") == 0) {
                sprintf(d_path, "%s/%s/%s", dirname, dirp->d_name, src_arch);
                ret = search_directory(d_path, level + 2);
            } else {
                sprintf(d_path, "%s/%s", dirname, dirp->d_name);
                ret = search_directory(d_path, level + 1);
            }

            if (ret)
                return ret;
        } else {
            if (strcmp(dirp->d_name, "Makefile") == 0) {
                sprintf(d_path, "%s/%s", dirname, dirp->d_name);
                parse_makefile(d_path);
                //printf("%s %s\n", "FILE", d_path);
            }
        }
    }

    closedir(dir);
    return 0;
}

static void get_mod_list(void)
{
    DIR *dir;
    struct dirent *dirp;

    dir=opendir("/sys/module/");
    if (!dir) {
	    perror("cannot open /sys/module\n");
	    exit(-1);
    }

    while((dirp=readdir(dir))!=NULL) {
        if(dirp->d_type == DT_DIR) {
            if(strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0) {
                continue;
            }

            struct mod_config *pos;
            list_for_each_entry(pos, &module_config_list, node) {
                if (!strcmp(dirp->d_name, pos->mod_name)) {
                    printf("%s: loaded\n", dirp->d_name);
                    pos->loaded = true;
                    //break;
                }
            }
        }
    }
    closedir(dir);
}

int conf_read_load_stat(void)
{
    int ret;

    printf("%s\n", regexstr);
    ret = regcomp(&regex_compiled, regexstr, REG_EXTENDED);
    if (ret) {
        perror("Could not compile regular expression.\n");
        return -1;
    };

    src_arch = getenv("SRCARCH");
    if (!src_arch) {
        fprintf(stderr, "cannot get SRCARCH\n");
        return -1;
    }

    search_directory("/home/changbin/work/linux", 0);
    get_mod_list();

    struct mod_config *pos;
    list_for_each_entry(pos, &module_config_list, node) {
	    if (!pos->loaded)
		    continue;

        struct symbol *sym = sym_get_by_name(pos->conf_name);
        if (sym)
            sym->flags |= SYMBOL_LOADED;
    }

    regfree(&regex_compiled);
    return 0;
}
