#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>


#define LINE_MAX_LEN 1024
#define MAX_ARGS 64

// Códigos ANSI para los colores e estilos del texto
#define ANSI_BOLD "\x1b[1m"
#define ANSI_RESET "\x1b[0m"
#define ANSI_BLUE "\x1b[34m"
#define ANSI_GREEN "\x1b[32m"
#define ANSI_YELLOW "\x1b[33m"



void print_prompt(void) {
	char cwd[PATH_MAX];
	const char* user = getenv("USER");
	if (!user) user = "user";
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

int parse_line(char* line, char** argv, int max_args) {
	int argc = 0;
	const char* delim = " \t\n";
	char* token = strtok(line, delim);
	while (token != NULL && argc < max_args - 1) {
		argv[argc++] = token;
		token = strtok(NULL, delim);
	}
	argv[argc] = NULL
	return argc;
}

int main(int argc, char* argv[]) {
	if (strcmp(args[0], "exit") == 0) {
		printf("%sCerrando minishell. Hasta luego!%s\n", ANSI_YELLOW, ANSI_RESET);
		break;
	}
	else if (strcmp(args[0], "cd") == 0) {
		printf("%s[internal] cd -> cambiar directorio a: %s%s\n",
			ANSI_YELLOW,
			(argcount > 1 ? args[1] : "(HOME)"),
			ANSI_RESET);
		continue;
	}
	else if (strcmp(args[0], "export") == 0) {
		printf("%s[internal] export -> establecer variable de entorno: %s%s\n",
			ANSI_YELLOW,
			(argcount > 1 ? args[1] : "(none)"),
			ANSI_RESET);
		continue;
	}
	else if (strcmp(args[0], "source") == 0) {
		printf("%s[internal] source -> ejecutar comandos desde archivo: %s%s\n",
			ANSI_YELLOW,
			(argcount > 1 ? args[1] : "(none)"),
			ANSI_RESET);
		continue;
	}
	else if (strcmp(args[0], "jobs") == 0) {
		printf("%s[internal] jobs -> listar trabajos en background (placeholder)%s\n",
			ANSI_YELLOW, ANSI_RESET);
		continue;
	}
	else if (strcmp(args[0], "fg") == 0) {
		printf("%s[internal] fg -> traer trabajo al foreground (placeholder)%s\n",
			ANSI_YELLOW, ANSI_RESET);
		continue;
	}
	else if (strcmp(args[0], "bg") == 0) {
		printf("%s[internal] bg -> enviar trabajo a background (placeholder)%s\n",
			ANSI_YELLOW, ANSI_RESET);
		continue;
	}

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		continue;
	}
	if (pid == 0) {
		execvp(args[0], args);
		perror("execvp");
		_exit(EXIT_FAILURE);
	}
	else {
		int status;
		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
		}
	}
}


return 0;
}
