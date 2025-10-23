#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>

// Es defineix el tamany i els arguments limit d'una comanda
#define LINE_MAX_LEN 1024
#define MAX_ARGS 64

// Codis ansi per al estil i color del texte
#define ANSI_BOLD "\x1b[1m" // Texte en negreta
#define ANSI_RESET "\x1b[0m" // Reinicialització del format
#define ANSI_BLUE "\x1b[34m" // Blau
#define ANSI_GREEN "\x1b[32m" // Verd
#define ANSI_YELLOW "\x1b[33m" // Groc


// Mètode que imprimeix per pantalla la comanda de l'usuari
void print_prompt(void) {
	char cwd[PATH_MAX];
	const char* user = getenv("USER"); // Es defineix el nom del 'user'
	if (!user) user = "user"; // En cas de que l'usuari no sigui 'user'
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

int execute_line(char* line) {};

int check_internal(char** args) {
	if (args == NULL || args[0] == NULL) return 0;


	if (strcmp(args[0], "exit") == 0) { // Comanda per a sortir del programa
		printf("Bye Bye\n");
		exit(EXIT_SUCCESS);
	}
	// Altres comandes sense funcionalitat temporalment
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

int internal_cd(char** args) {};

int internal_export(char** args) {};

int internal_source(char** args) {};

int internal_jobs() {};

int internal_fg(char** args) {};

int internal_bg(char** args) {};


// Mètode main del programa que inclou el bucle principal temporal per a 
// imprimir les comandes de l'usuari i sortir del programa
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
