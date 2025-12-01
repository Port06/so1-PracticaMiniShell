#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdarg.h>
#include <signal.h>

// Es defineix el tamany i els arguments limit d'una comanda
#define LINE_MAX_LEN 1024
#define MAX_ARGS 64

#define N_JOBS 64

// Codis ansi per al estil i color del texte
#define ANSI_BOLD "\x1b[1m" // Texte en negreta
#define ANSI_RESET "\x1b[0m" // Reinicialitzaci� del format
#define ANSI_BLUE "\x1b[34m" // Blau
#define ANSI_GREEN "\x1b[32m" // Verd
#define ANSI_YELLOW "\x1b[33m" // Groc

int debugN1 = 0;
int debugN2 = 1;

void debug(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

//pequeño strndup local por si no existe en el entorno
static char* strndup_local(const char* s, size_t n) {
	size_t len = strnlen(s, n);
	char* p = malloc(len + 1);
	if (!p) return NULL;
	memcpy(p, s, len);
	p[len] = '\0';
	return p;
}

struct info_job {
	pid_t pid;
	char status;
	char cmd[LINE_MAX_LEN];
};

static int n_jobs = 1; // TODO: hauria de ser 0 o 1??
static struct info_job jobs_list[N_JOBS];
static char my_shell[LINE_MAX_LEN];

// prototipos
int internal_cd(char** args);
int internal_export(char** args);
int internal_source(char** args);
int internal_jobs(char** args);
int internal_fg(char** args);
int internal_bg(char** args);
int check_internal(char** args);
int execute_line(char* line);

// jobs_list_add: intenta afegir un job al final de la llista de jobs
// retorna 0 si s'ha pogut afegir, o -1 en cas d'error (llista plena)
int jobs_list_add(pid_t pid, char status, char *cmd) {
	if (n_jobs < N_JOBS) {
		jobs_list[n_jobs].pid = pid;
		jobs_list[n_jobs].status = status;

		strncpy(jobs_list[n_jobs].cmd, cmd, LINE_MAX_LEN - 1);
		jobs_list[n_jobs].cmd[LINE_MAX_LEN - 1] = '\0';

		n_jobs++;
		return 0;
	} else {
		return -1;
	}
}

// jobs_list_find: cerca un proces amb PID determinat dins la llista de jobs
// retorna la posicio del process, o -1 si no s'ha trobat
int jobs_list_find(pid_t pid) {
	for (int i = 0; i < n_jobs; i++) {
		if (jobs_list[i].pid == pid)
			return i;
	}

	return -1;
}

// jobs_list_remove: elimina un job de la llista de jobs
// retorna 0 si s'ha pogut eliminar, o -1 en cas d'error (posicio invalida)
int jobs_list_remove(int pos) {
	if (pos >= n_jobs || pos < 0)
		return -1;

	// decrementam primer n_jobs i despres intercanviam el darrer job amb el job situat a pos
	jobs_list[pos] = jobs_list[--n_jobs];
	return 0;
}

// M�tode que imprimeix per pantalla la comanda de l'usuari
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
	debug("[internal_exit] bye bye\n");
	exit(EXIT_SUCCESS);
}

char* read_line(char* line, size_t len) {
	print_prompt();

	if (fgets(line, len, stdin) == NULL) {
		if (feof(stdin)) { // Usuari ha pitjat Ctrl+D
			debug("\n[read_line] EOF\n");
			internal_exit();
		}
		else {
			return NULL;
		}
	}

	char* newline = strchr(line, '\n');
	if (newline != NULL) *newline = '\0'; // Eliminam la newline final, si n'hi ha
	return line;
}

// is_background: detecta '&' als arguments
int is_background(char *line) {
	char *found = strchr(line, '&');
	if (found == NULL)
		return 0;

	*found = '\0';
	return 1;
}

// parse_line: tokenitza i talla en '#' (comentaris). No afageix NULL com a token
// parse_line que respeta comillas simples y dobles, y corta en '#' (comentarios)
int parse_line(char* line, char** argv, int max_args) {
	int argc = 0;
	char* p = line;

	while (*p != '\0' && argc < max_args - 1) {
		// saltar espacios
		while (*p == ' ' || *p == '\t' || *p == '\n') p++;
		if (*p == '\0' || *p == '#') break;

		if (*p == '"' || *p == '\'') {
			char quote = *p++;
			char* start = p;
			// buscar cierre de comilla
			while (*p != '\0' && *p != quote) {
				if (*p == '\\' && *(p + 1) != '\0') p += 2; // permitir escapes simples
				else p++;
			}
			if (*p == quote) {
				*p = '\0';
				argv[argc++] = start;
				p++; // avanzar después de la comilla final
			}
			else {
				// comilla no cerrada: tomar hasta el final
				argv[argc++] = start;
				break;
			}
		}
		else {
			char* start = p;
			while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#') p++;
			if (*p == '#') {
				// terminar token y descartar resto -> comentario
				*p = '\0';
				argv[argc++] = start;
				break;
			}
			if (*p != '\0') {
				*p = '\0';
				argv[argc++] = start;
				p++;
			}
			else {
				argv[argc++] = start;
				break;
			}
		}
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

	// Si no hay argumento -> HOME
	if (args == NULL || args[1] == NULL) {
		target = getenv("HOME");
		if (target == NULL) {
			fprintf(stderr, "cd: HOME no definido\n");
			return 1;
		}
	}
	else {
		target = args[1];  // El parser ya devuelve la ruta completa, sin comillas
	}

	if (chdir(target) != 0) {
		perror("cd");
		return 1;
	}

	// Actualizar PWD y mostrar cwd
	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		perror("cd");
		return 1;
	}

	debug("[internal_cd] %s\n", cwd);
	if (setenv("PWD", cwd, 1) != 0) {
		perror("cd");
		// no abortamos, ya cambiamos de directorio
	}

	return 1;
}

//internal_export: parsea NOMBRE=VALOR en args[1], muestra antes y después (modo test)
int internal_export(char** args) {
	// Comprueba que se haya pasado un argumento (NOMBRE=VALOR)
	if (args == NULL || args[1] == NULL) {
		fprintf(stderr, "export: sintaxis correcta: export NOMBRE=VALOR\n");
		return 1;
	}

	// Separa el nombre y el valor buscando '='
	char* pair = args[1];
	char* eq = strchr(pair, '=');
	if (eq == NULL || eq == pair) {
		fprintf(stderr, "export: sintaxis correcta: export NOMBRE=VALOR\n");
		return 1;
	}

	// Extrae el nombre de la variable
	size_t name_len = eq - pair;
	char* name = strndup_local(pair, name_len);
	if (!name) {
		perror("");
		return 1;
	}

	char* value = strdup(eq + 1);
	if (!value) {
		free(name);
		perror("");
		return 1;
	}

	char* before = getenv(name);
	if (before != NULL)
		debug("[internal_export] %s=%s\n", name, before);
	else
		debug("[internal_export] %s was previously undefined\n", name);

	// Define (o sobrescribe) la variable de entorno
	if (setenv(name, value, 1) != 0) {
		perror("");
		free(name); free(value);
		return 1;
	}

	char* after = getenv(name);
	if (after != NULL)
		debug("[internal_export] %s=%s\n", name, after);
	else
		fprintf(stderr, "export: error inesperado al leer %s\n", name);

	// Libera la memoria reservada
	free(name);
	free(value);
	return 1;
}

// internal_source: llegeix linia per linia un fitxer, i executa cada linia
int internal_source(char** args) {
	if (args == NULL || args[1] == NULL) {
        fprintf(stderr, "source: expected file argument\n");
        return 1;
	}

	debug("[internal_source] reading from file %s\n", args[1]);

	FILE* file = fopen(args[1], "r");
	if (file == NULL) {
		perror("fopen");
		return 1;
	}

	char line[LINE_MAX_LEN];

	while (fgets(line, LINE_MAX_LEN, file) != NULL) {
		fflush(file);

		char *newline = strchr(line, '\n');
		if (newline != NULL) // Si hi ha \n a la linia, l'eliminam
			*newline = '\0';

		execute_line(line);
	}

	fclose(file);

	return 1;
}

// Recorrera jobs_list[] imprimint per pantalla els identificadors de feina entre corchetes (a partir de l'1), el seu PID, la linia de comandaments i l'estat (D de Detingut, E d'Executat)
// Important formatejar bé les dades amb tabuladors i en el mateix ordre que el Job del Bash
int internal_jobs(char** args) {
	debug("[internal_jobs] n_jobs = %d\n", n_jobs);

	for (int i = 1; i < n_jobs; i++) {
		printf("[%d] %d\t%c\t%s\n",
			i,
			jobs_list[i].pid,
			jobs_list[i].status,
			jobs_list[i].cmd);
	}

	return 1;
}

int internal_fg(char** args) {
	if (args == NULL || args[1] == NULL) {
        fprintf(stderr, "fg: expected job number argument\n");
        return 1;
	}

	int pos = atoi(args[1]);

	if (pos >= n_jobs || pos == 0) {
		fprintf(stderr, "fg: no such job\n");
		return 1;
	}

	struct info_job job = jobs_list[pos];

	// Si el job esta detingut, enviam SIGCONT
	if (job.status == 'D') {
		kill(job.pid, SIGCONT);
		debug("[internal_fg] signal SIGCONT sent to %d (%s)\n", job.pid, job.cmd);
	}

	// Eliminam el '&' final del cmd (si n'hi ha)
	char* found = strchr(job.cmd, '&');
	if (found != NULL)
		*found = '\0';

	// Afegim el job al foreground
	jobs_list[0].pid = job.pid;
	jobs_list[0].status = 'E';

	strncpy(jobs_list[0].cmd, job.cmd, LINE_MAX_LEN - 1);
	jobs_list[0].cmd[LINE_MAX_LEN - 1] = '\0';

	jobs_list_remove(pos); // i l'eliminam del background

	printf("%s\n", job.cmd); // NO ha de ser debug

	while (jobs_list[0].pid != 0)
		pause(); // Esperam fins que acabi el proces i sigui tractat pel reaper

	return 1;
}

int internal_bg(char** args) {
	debug("[internal_bg] This function will resume a suspended job in the background in later phases.\n");
	return 0;
};

void reaper(int signum) {
	(void)signum;  // Evita el warning de parámetro no usado (la señal recibida)
	signal(SIGCHLD, reaper);  // Reasociamos el manejador a la señal SIGCHLD

	pid_t ended;
	int status;

	debug("[reaper] reaper invoked, waiting for children...\n");

	// Recolectamos TODOS los hijos que hayan terminado sin bloquear
	while ((ended = waitpid(-1, &status, WNOHANG)) > 0) {
		int pos = jobs_list_find(ended);

		// Caso 1: el proceso terminó de forma normal (exit)
		if (WIFEXITED(status)) {
			int exitcode = WEXITSTATUS(status);
			debug("[reaper] child process %d (%s) finished with exit code %d\n", ended, jobs_list[pos].cmd, exitcode);

		// Caso 2: el proceso terminó por una señal
		} else if (WIFSIGNALED(status)) {
			int sig = WTERMSIG(status);
			debug("[reaper] child process %d (%s) terminated by signal %d\n", ended, jobs_list[pos].cmd, sig);

		// Caso 3: otro tipo de terminación (poco habitual)
		} else {
			debug("[reaper] child process %d finished (status %d)\n", ended, status);
		}

		// Si s'executava en foreground (posicio 0), posam el job a 0
		if (pos == 0) {
			jobs_list[0].pid = 0;
			jobs_list[0].status = 'F';
			jobs_list[0].cmd[0] = '\0';
		} else {
			// TODO: aqui que hem d'imprimir exactament?
			printf("child process %d (%s) ended\n", jobs_list[pos].pid, jobs_list[pos].cmd); // NO ha de ser debug, s'ha d'imprimir sempre

			jobs_list_remove(pos);
		}
	}

	debug("[reaper] finished, returning...\n");
}

void ctrlc(int signum) {
	(void)signum;
	signal(SIGINT, ctrlc); // re-armar el manejador

	pid_t fg = jobs_list[0].pid; // Val 0 si no hi ha foreground
	pid_t me = getpid();

	debug("\n[ctrlc] received by process %d (%s), foreground process is %d (%s)\n",
		me,
		my_shell,
		fg,
		(fg ? jobs_list[0].cmd : ""));

	if (fg > 0) {
		if (fg != me) {
			// enviar SIGTERM al proceso foreground (no al shell)
			if (kill(fg, SIGTERM) == 0)
				debug("[ctrlc] signal 15 (SIGTERM) sent to %d (%s) by %d (%s)\n", fg, jobs_list[0].cmd, me, my_shell);
			else
				perror("kill");
		} else {
			debug("[ctrlc] signal 15 not sent by %d (%s): foreground process is the shell\n", me, my_shell);
		}
	} else {
		debug("[ctrlc] signal 15 not sent by %d (%s): no foreground process\n", me, my_shell);
	}
}

void ctrlz(int signum) {
	signal(SIGTSTP, ctrlz); // re-armar el manejador

	pid_t fg = jobs_list[0].pid; // Val 0 si no hi ha foreground
	pid_t me = getpid();

	debug("\n[ctrlz] received by process %d (%s), foreground process is %d (%s)\n",
		me,
		my_shell,
		fg,
		(fg ? jobs_list[0].cmd : ""));

	if (fg > 0) { // Hi ha processos en foreground
		if (fg != me) {
			if (kill(fg, SIGSTOP) == 0) {
				debug("[ctrlz] signal SIGSTOP sent to %d by %d (%s)\n", fg, me, my_shell);

				// Movem el process de foreground al background
				jobs_list_add(fg, 'D', jobs_list[0].cmd);

				// Resetejam el job numero 0 (foreground), perque execute_line finalitzi
				// l'execucio i tornem al bucle del main
				jobs_list[0] = (struct info_job) {0};
			} else {
				perror("kill");
			}
		} else {
			debug("[ctrlz] signal SIGSTOP not sent by %d (%s): foreground process is the shell\n", me, my_shell);
		}
	} else {
		debug("[ctrlz] signal SIGSTOP not sent by %d (%s): no foreground process\n", me, my_shell);
	}
}

int check_internal(char** args) {
	if (args == NULL || args[0] == NULL)
		return 0;

	if (strcmp(args[0], "exit") == 0) {
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

/* Ejecuta la linea: si interno -> ya manejado, si no -> fork + execvp */
int execute_line(char* line) {
	int isbg = is_background(line);

	char* argv[MAX_ARGS];
	char* cmd = line;
	int argc = parse_line(line, argv, MAX_ARGS);

	if (argc == 0)
		return 0;

	if (check_internal(argv))
		return 1;

	// Inicialitzam mascares buides
	sigset_t mask, oldmask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	// Bloquejam temporalment SIGCHLD, de manera que el reaper no es pugui executar
	// abans d'haver inicialitzat la llista de jobs
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		// FILL

		signal(SIGINT, SIG_IGN); // Ignoram SIGINT
		signal(SIGTSTP, SIG_IGN); // Ignoram SIGTSTP

		// Necessitam restaurar la mascara anterior, perque execvp() preserva la
		// mascara i volem que el fill no tengui restriccions
		sigprocmask(SIG_SETMASK, &oldmask, NULL);

		// Executam la comanda
		execvp(argv[0], argv);

		perror(argv[0]);
		_exit(EXIT_FAILURE);
	} else if (pid > 0) {
		// PARE

		debug("[execute_line] fork: parent PID: %d (%s)]\n", getpid(), my_shell);
		debug("[execute_line] fork: child PID: %d (%s)]\n", pid, cmd);

		if (isbg) {
			jobs_list_add(pid, 'E', cmd);
			sigprocmask(SIG_SETMASK, &oldmask, NULL); // Permetem que el reaper actui
		} else { // Introduim el process a la llista com a foreground
			jobs_list[0].pid = pid;
			jobs_list[0].status = 'E';
			strncpy(jobs_list[0].cmd, cmd, LINE_MAX_LEN - 1);
			jobs_list[0].cmd[LINE_MAX_LEN - 1] = '\0';

			sigprocmask(SIG_SETMASK, &oldmask, NULL); // Permetem que el reaper actui
			debug("[execute_line] waiting for reaper\n");

			while (jobs_list[0].pid != 0)
				pause();
		}
	} else {
		perror("fork");
	}

	return 1;
}

int main(int argc, char** argv) {
	jobs_list[0].pid = 0;
	jobs_list[0].status = 'N';
	memset(jobs_list[0].cmd, '\0', LINE_MAX_LEN);

	// Registram els manetjadors
	signal(SIGCHLD, reaper);
	signal(SIGINT, ctrlc);
	signal(SIGTSTP, ctrlz);

	strncpy(my_shell, argv[0], LINE_MAX_LEN);

	while (1) {
		char line[LINE_MAX_LEN];
		if (read_line(line, sizeof(line)) == NULL)
			continue;

		execute_line(line);

		jobs_list[0].pid = 0;
		jobs_list[0].status = 'N';
		memset(jobs_list[0].cmd, '\0', LINE_MAX_LEN);
	}

	return 0;
}
