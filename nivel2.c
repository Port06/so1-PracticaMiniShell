/* nivel2.c - minishell (cd y export implementados, versión corregida) */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdarg.h>

// es defineix el tamany i els arguments limit d'una comanda
#define LINE_MAX_LEN 1024
#define MAX_ARGS 64

// codis ansi per al estil i color del texte
#define ANSI_BOLD "\x1b[1m" // texte en negreta
#define ANSI_RESET "\x1b[0m" // reinicialitzaci� del format
#define ANSI_BLUE "\x1b[34m" // blau
#define ANSI_GREEN "\x1b[32m" // verd
#define ANSI_YELLOW "\x1b[33m" // groc

int debugN1 = 0;
int debugN2 = 1;

void debug(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

// petit strndup local per si no existeix en el entorn
static char* strndup_local(const char* s, size_t n) {
    size_t len = strnlen(s, n);
    char* p = malloc(len + 1);
    if (!p) return NULL;
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

// prototipos
int internal_cd(char** args);
int internal_export(char** args);
int internal_source(char** args);
int internal_jobs();
int internal_fg(char** args);
int internal_bg(char** args);
int check_internal(char** args);

// metode que imprimeix per pantalla la comanda de l'usuari
void print_prompt(void) {
    char cwd[LINE_MAX_LEN];
    const char* user = getenv("USER");
    if (user == NULL) user = "user";

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strncpy(cwd, "?", sizeof(cwd));
        cwd[sizeof(cwd) - 1] = '\0';
    }

    printf("%s[%s%s%s:%s%s%s]%s$ %s",
        ANSI_BOLD,
        ANSI_GREEN, user, ANSI_RESET,
        ANSI_BLUE, cwd, ANSI_RESET,
        ANSI_BOLD,
        ANSI_RESET);
    fflush(stdout);
}

void internal_exit() {
    debug("exit\n");
    printf("Bye Bye\n");
    exit(EXIT_SUCCESS);
}

char* read_line(char* line, size_t len) {
    print_prompt();

    if (fgets(line, len, stdin) == NULL) {
        if (feof(stdin)) { // usuari ha pitjat Ctrl+D
            debug("\n[read_line] EOF\n");
            internal_exit();
        }
        else {
            return NULL;
        }
    }

    char* newline = strchr(line, '\n');
    if (newline != NULL) *newline = '\0'; // eliminar la newline final, si n'hi ha
    return line;
}

// parse_line: tokenitza i talla en '#' (comentaris). No afageix NULL com a token
int parse_line(char* line, char** argv, int max_args) {
    int argc = 0;
    const char* delim = " \t\n";
    char* token = strtok(line, delim);

    while (token != NULL && argc < max_args - 1) {
        if (token[0] == '#') { // Si comenca per #, hem d'ignorar el token
            break; // ignorar el que queda de la linia
        }
        argv[argc++] = token;
        token = strtok(NULL, delim);
    }
    argv[argc] = NULL;

    for (int i = 0; i <= argc; ++i)
        debug("[parse_line] token %d: %s\n", i, argv[i] ? argv[i] : "(null)");

    return argc;
}

// internal_cd: implementa cd sin args -> HOME, un arg, o varios (concatena y quita comillas) 
int internal_cd(char** args) {
    char* target = NULL;
    char cwd[LINE_MAX_LEN];
    int target_malloced = 0;

    if (args == NULL || args[1] == NULL) {
        target = getenv("HOME");
        if (target == NULL) {
            fprintf(stderr, "cd: HOME no definido\n");
            return 1;
        }
    }
    else {
        if (args[2] == NULL) {
            target = args[1];
        }
        else {
            size_t bufsize = LINE_MAX_LEN;
            char* buf = malloc(bufsize);
            if (!buf) { perror(""); return 1; }
            buf[0] = '\0';
            for (int i = 1; args[i] != NULL; ++i) {
                size_t need = strlen(buf) + strlen(args[i]) + 2;
                if (need > bufsize) {
                    bufsize = need * 2;
                    char* tmp = realloc(buf, bufsize);
                    if (!tmp) { free(buf); perror(""); return 1; }
                    buf = tmp;
                }
                if (buf[0] != '\0') strcat(buf, " ");
                strcat(buf, args[i]);
            }
            // retirar les cometes presents a les instruccions
            size_t len = strlen(buf);
            if (len >= 2 && ((buf[0] == '\'' && buf[len - 1] == '\'') || (buf[0] == '"' && buf[len - 1] == '"'))) {
                buf[len - 1] = ' ';
                char* copy = strndup_local(buf + 1, strlen(buf + 1));
                free(buf);
                if (!copy) { perror(""); return 1; }
                target = copy;
                target_malloced = 1;
            }
            else {
                target = buf;
                target_malloced = 1; // es llibera el final
            }
        }
    }

    if (chdir(target) != 0) {
        perror("");
        if (target_malloced) free(target);
        return 1;
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("");
        if (target_malloced) free(target);
        return 1;
    }
    else {
        // mostrar cwd (solo en este nivel de práctica) 
        printf("%s\n", cwd);
        // actualitzar PWD en entorn
        if (setenv("PWD", cwd, 1) != 0) {
            perror("");
            // no abortam: ja que hem cambiat de cwd 
        }
    }

    if (target_malloced) free(target);
    return 1;
}

//internal_export: parseja NOMBRE=VALOR en args[1], mostra mostra abans i despres
int internal_export(char** args) {
    if (args == NULL || args[1] == NULL) {
        fprintf(stderr, "export: sintaxis correcta: export NOMBRE=VALOR\n");
        return 1;
    }

    char* pair = args[1];
    char* eq = strchr(pair, '=');
    if (eq == NULL || eq == pair) {
        fprintf(stderr, "export: sintaxis correcta: export NOMBRE=VALOR\n");
        return 1;
    }

    size_t name_len = eq - pair;
    char* name = strndup_local(pair, name_len);
    if (!name) { perror(""); return 1; }
    char* value = strdup(eq + 1);
    if (!value) { free(name); perror(""); return 1; }

    char* before = getenv(name);
    if (before != NULL) {
        printf("%s=%s\n", name, before);
    }
    else {
        printf("%s no estaba definida\n", name);
    }

    if (setenv(name, value, 1) != 0) {
        perror("");
        free(name); free(value);
        return 1;
    }

    char* after = getenv(name);
    if (after != NULL) {
        printf("%s=%s\n", name, after);
    }
    else {
        fprintf(stderr, "export: error inesperado al leer %s\n", name);
    }

    free(name);
    free(value);
    return 1;
}

// stubs coherents
int internal_source(char** args) {
	debug("[internal_source] This function will read and execute commands from a file in later phases.\n");
	return 0;
};

int internal_jobs() {
	debug("[internal_jobs] This function will list background jobs in later phases.\n");
	return 0;
};

int internal_fg(char** args) {
	debug("[internal_fg] This function will bring a background job to the foreground in later phases.\n");
	return 0;
};

int internal_bg(char** args) {
	debug("[internal_bg] This function will resume a suspended job in the background in later phases.\n");
	return 0;
};

int check_internal(char** args) {
    if (args == NULL || args[0] == NULL) return 0;

    if (strcmp(args[0], "exit") == 0) {
        debug("[internal] exit\n");
        internal_exit();
    }
    else if (strcmp(args[0], "cd") == 0) {
        return internal_cd(args);
    }
    else if (strcmp(args[0], "export") == 0) {
        return internal_export(args);
    }
    else if (strcmp(args[0], "source") == 0) {
        return internal_source(args);
    }
    else if (strcmp(args[0], "jobs") == 0) {
        return internal_jobs(args);
    }
    else if (strcmp(args[0], "fg") == 0) {
        return internal_fg(args);
    }
    else if (strcmp(args[0], "bg") == 0) {
        return internal_bg(args);
    }
    return 0;
}

// executa la linea: si es intern -> ja manetjat, si no -> fork + execvp */
int execute_line(char* line) {
    char* argv[MAX_ARGS];
    int argc = parse_line(line, argv, MAX_ARGS);

    if (argc == 0) return 0;

    if (check_internal(argv)) return 1;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        perror("");
        _exit(EXIT_FAILURE);
    }
    else {
        int status;
        if (waitpid(pid, &status, 0) < 0) perror("waitpid");
    }
    return 1;
}

int main(void) {
    while (1) {
        char line[LINE_MAX_LEN];
        if (read_line(line, sizeof(line)) == NULL) continue;
        execute_line(line);
    }
    return 0;
}
