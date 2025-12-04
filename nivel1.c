// Autors: Marc Xavier Arrom, Loan Besnardeau, Joshua Zien

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>

#include <stdarg.h>

// Es defineix el tamany i els arguments limit d'una comanda
#define LINE_MAX_LEN 1024
#define MAX_ARGS 64

// Codis ansi per al estil i color del texte
#define ANSI_BOLD "\x1b[1m" // Texte en negreta
#define ANSI_RESET "\x1b[0m" // Reinicialitzaci� del format
#define ANSI_BLUE "\x1b[34m" // Blau
#define ANSI_GREEN "\x1b[32m" // Verd
#define ANSI_YELLOW "\x1b[33m" // Groc

#define DEBUG_N1 1
#define DEBUG_N2 0
#define DEBUG_N3 0
#define DEBUG_N4 0
#define DEBUG_N5 0
#define DEBUG_N6 0

void debug(int level, char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);

	if (level)
		vfprintf(stderr, fmt, ap);

	va_end(ap);
}

// M�tode que imprimeix per pantalla la comanda de l'usuari
void print_prompt(void) {
	char cwd[LINE_MAX_LEN];
	const char* user = getenv("USER"); // Es defineix el nom del 'user'
	
	if (user == NULL)
		user = "user"; // En cas de que l'usuari no sigui 'user'

	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		strncpy(cwd, "?", sizeof(cwd));
		cwd[sizeof(cwd) - 1] = '\0';
	}

	printf("%s[%s%s%s:%s%s%s]%s$ %s", // Imprimeix el texte amb el format adequat
		ANSI_BOLD,
		ANSI_GREEN, user, ANSI_RESET,
		ANSI_BLUE, cwd, ANSI_RESET,
		ANSI_BOLD,
		ANSI_RESET);

	fflush(stdout);
}

void internal_exit() {
	debug(DEBUG_N1, "exit\n");
	exit(EXIT_SUCCESS);
}

char *read_line(char *line, size_t len) {
	print_prompt();

	if (fgets(line, len, stdin) == NULL) {
		if (feof(stdin)) { // Usuari ha pitjat Ctrl+D
			debug(DEBUG_N1, "\n[read_line] ");
			internal_exit();
		} else {
			return NULL;
		}
	}

	char *newline = strchr(line, '\n');
	if (newline != NULL) // Eliminam la newline final, si n'hi ha
		*newline = '\0';

	return line;
}

int parse_line(char* line, char** argv, int max_args) {
	int argc = 0;
	const char* delim = " \t\n";
	char* token = strtok(line, delim);

	while (token != NULL && argc < max_args - 1) {
		if (*token == '#') // Si comenca per #, hem d'ignorar el token
			token = NULL;

		argv[argc++] = token;
		token = strtok(NULL, delim);
	}

	argv[argc] = NULL;

	for (int i = 0; i <= argc; i++)
		debug(DEBUG_N1, "[parse_line] token %i: %s\n", i, argv[i]);

	return argc;
}

int internal_cd(char** args) {
	char *path;

	if (args[1] == NULL)
		path = getenv("HOME");
	else
		path = args[1];

	chdir(path);

	char cwd[LINE_MAX_LEN];
	if (getcwd(cwd, sizeof(cwd) / sizeof(char)) != NULL)
		debug(DEBUG_N2, "[internal_cd] getcwd is %s\n", cwd);
	else
		debug(DEBUG_N2, "[internal_cd] error while getcwd()\n");

	return 0;
}

int internal_export(char** args) {
	debug(DEBUG_N1, "[internal_export] This function will set environment variables in later phases.\n");
	return 0;
};

int internal_source(char** args) {
	debug(DEBUG_N1, "[internal_source] This function will read and execute commands from a file in later phases.\n");
	return 0;
};

int internal_jobs() {
	debug(DEBUG_N1, "[internal_jobs] This function will list background jobs in later phases.\n");
	return 0;
};

int internal_fg(char** args) {
	debug(DEBUG_N1, "[internal_fg] This function will bring a background job to the foreground in later phases.\n");
	return 0;
};

int internal_bg(char** args) {
	debug(DEBUG_N1, "[internal_bg] This function will resume a suspended job in the background in later phases.\n");
	return 0;
};

int check_internal(char** args) {
	if (args == NULL || args[0] == NULL)
		return 0;

	if (strcmp(args[0], "exit") == 0) { // Comanda per a sortir del programa
		debug(DEBUG_N1, "[internal] ");
		internal_exit();
	}

	// Altres comandes sense funcionalitat temporalment
	else if (strcmp(args[0], "cd") == 0) {
		return internal_cd(args);
	} else if (strcmp(args[0], "export") == 0) {
		return internal_export(args);
	} else if (strcmp(args[0], "source") == 0) {
		return internal_source(args);
	} else if (strcmp(args[0], "jobs") == 0) {
		return internal_jobs(args);
	} else if (strcmp(args[0], "fg") == 0) {
		return internal_fg(args);
	} else if (strcmp(args[0], "bg") == 0) {
		return internal_bg(args);
	}

	return 0;
}

int execute_line(char* line) {
	char *argv[MAX_ARGS];
	int argc = parse_line(line, argv, MAX_ARGS);

	if (argc == 0)
		return 0;

	check_internal(argv);
	return 1;
}

int main(void) {
	while (1) {
		char line[LINE_MAX_LEN];
		if (read_line(line, sizeof(line) / sizeof(char)) == NULL)
			continue;

		execute_line(line);
	}
}
