#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define MIN_FILE_SIZE 4096
#define NUM_BYTES_PER_ROW	16

static void print_hex(FILE *out, char *k)
{
	short i, byte = NUM_BYTES_PER_ROW;
	char *p = k;
	while(*p)
	{
		i = 0;
		fprintf(out, "%#10.8x ", byte);
		while(*p && i++ < NUM_BYTES_PER_ROW)
			fprintf(out, "%x ", (int) *p++);
		putc('\n', out);
		byte += NUM_BYTES_PER_ROW;
	}
}

static struct randfile
{
    char *name;
    unsigned short ok;
    int fd;
    int size;
    int goodness;
    int special;
}
ftable[] =
{
    {"/dev/urandom", 0, -1, 0, 256, 1},
    {"/dev/random", 0, -1, 0, 64, 1},
    {"/var/log/messages", 0, -1, -1, 4, 0},
    {"/var/adm/messages", 0, -1, -1, 4, 0},
    {"/var/adm/syslog", 0, -1, -1, 4, 0},
    {"/var/log/system.log", 0, -1, -1, 4, 0},
    {"/var/wtmp", 0, -1, -1, 2, 0},
    {"/kernel", 0, -1, -1, 2, 0},
    {"/kernel/genunix", 0, -1, -1, 2, 0},
    {"/vmunix", 0, -1, -1, 2, 0},
    {"/vmlinuz", 0, -1, -1, 2, 0},
    {"/boot/vmlinuz", 0, -1, -1, 2, 0},
    {"/netbsd", 0, -1, -1, 2, 0},
    {"/mach", 0, -1, -1, 2, 0},
    {"/mach_kernel", 0, -1, -1, 2, 0},
    {"/bin/ls", 0, -1, -1, 1, 0},
    {"/bin/cp", 0, -1, -1, 1, 0},
    {NULL, 0, 0, 0, 0, 0}
};

const static char uschars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_+[]{}:\"|;'\\,./<>?`~";

static void sweep(char *p)
{
    struct randfile *f;

    for(f = ftable; f->name; f++)
	if(f->ok)
	    (void) close(f->fd);

    free((void *)p);
}

int main(int ac, char **av)
{
    struct randfile *f = ftable;
    int bits, tbits;
    char *key, *k;
    struct stat st;
    int nfiles = 0;
    
    if(ac < 2)
    {
	printf("pass me the number of key bits !\n");
	exit(1);
    }
    else if((tbits = bits = (int) strtol(av[1], NULL, 10)) <= 0 ||
	    (bits % 8))
    {
	printf("invalid number of bits passed (%s), remember that bits must be a multiple of eigth\n", av[1]);
	exit(-1);
    }
    
    for(; f->name; f++)
    {
	if((access(f->name, R_OK) != -1) &&
		(f->fd = open(f->name, O_RDONLY)) &&
		(f->special || ((fstat(f->fd, &st) != -1) &&
		((f->size = st.st_size) > MIN_FILE_SIZE))))
	{
	    fprintf(stderr, "caugth %s, %d bytes large%s, goodness: %d\n",
		    f->name, f->size, f->special ? " (special file)" : "", f->goodness);
	    f->ok++;
	    nfiles++;
	}
	else if(f->fd != -1)
	    (void) close(f->fd);
    }

    if(ftable[1].ok)
	fprintf(stderr, "Notice: /dev/random caugth. if key generation freezes, \n"
		"type random strokes on the keyboard to speed it up.\n");

    if(!nfiles)
    {
	printf("no files available.\n");
	exit(-1);
    }

    k = key = malloc((bits / 8) + 1);

    srand(time(0)*getpid());

    while(nfiles && bits > 0)
    {
	int i, goodness;

	f = &ftable[rand() % (sizeof(ftable) / (sizeof(struct randfile) - 1))];
	if(!f->ok)
	    continue;
	else
	{
	    if(!f->special && lseek(f->fd, rand() % f->size, SEEK_SET) == -1)
	    {
		f->ok = 0;
		(void) close(f->fd);
		nfiles--;
		continue;
	    }

	    goodness = f->goodness;
	    while(goodness-- && bits)
	    {
		if(read(f->fd, (void *) &i, sizeof(int)) == -1)
		{
		    f->ok = 0;
		    (void) close(f->fd);
		    nfiles--;
		    continue;
		}

		*k++ = uschars[i % (sizeof(uschars) - 1)];
		bits -= 8;
		if(bits % (tbits / 8) == 0)
		    fprintf(stderr, "Got %d bits of random data . .\n", tbits - bits);
	    }
	    
	}
    }

    if(bits)
    {
	printf("not enough random data read !\n");
	sweep(key);
	exit(-1);
    }

    *k = '\0';

	fprintf(stderr, "\nhex output of the key:\n------------------------- ---- --- --- -- -- - -  -  -\n");
	print_hex(stderr, key);
	fprintf(stderr, "------------------------- ---- --- --- -- -- - -  -  -\n\n");

	fprintf(stdout, "%s", key);

    sweep(key);

    exit(0);
}
