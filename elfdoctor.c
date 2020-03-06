#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>

struct elf32 {
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Dyn *dynSegment;
	unsigned char *plt;
	unsigned char *got;
};

struct elf64 {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
};

pid_t pidMax(void);
void freeBobby(int, ...);
void readProcessMemory(pid_t, long, long, unsigned char *);
long extractBaseAddress(char *);
void parseElfHeaders(pid_t, long);

int main(int argc, char *argv[])
{
	pid_t targetPid, pidM = pidMax();
	char *mapsPath;
	long baseAddress;

	if (argc != 2) 
	{
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if ((targetPid = strtol(argv[1], NULL, 0)) == 0)
	{
		fprintf(stderr, "%s was not a valid pid\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	if (targetPid < 0 || targetPid > pidM)
	{
		fprintf(stderr, "%d exceed pid limit(set to %d)\n", targetPid, pidM);
		exit(EXIT_FAILURE);
	}
	mapsPath = calloc(strlen("/proc//maps") + strlen(argv[1]) + 1, sizeof(char));
	sprintf(mapsPath, "/proc/%d/maps", targetPid);
	baseAddress = extractBaseAddress(mapsPath);
	fprintf(stdout, "[*] - Found base @ 0x%lx\n", baseAddress);
	if (ptrace(PTRACE_ATTACH, targetPid, NULL, NULL) == -1)
	{
		if(errno == EPERM)
		{
			fprintf(stderr,"can not attach to %d(%s)\n", targetPid, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	parseElfHeaders(targetPid, baseAddress);
	ptrace(PTRACE_DETACH, targetPid, NULL, NULL);
	free(mapsPath);

	return 0;
}

void readProcessMemory(pid_t pid, long size, long addr, unsigned char *dest)
{
	int i = 0;
	int j = 0;
	long tmpy;
#ifdef DEBUG
	printf("[*] - Reading %4ld bytes from %d\n", size, pid); 
#endif
	while (size > 0)
	{
		/* prevent overflow if size % sizeof(long) != 0 */
		if (size >= sizeof(long))
			size -= sizeof(long);
		else
			break;
		*((long *)dest + i) = ptrace(PTRACE_PEEKTEXT, pid, (long *)addr + i, NULL);
		i++;
	}
	/* if size % sizeof(long) != 0, read last X bytes, byte per byte */
	if (size)
	{
		tmpy = ptrace(PTRACE_PEEKTEXT, pid, (long *)addr + i, NULL);
		while(size--)
		{
			dest[i * sizeof(long) + j] = *((unsigned char *)&tmpy + j);
			j++;
		}
	}
}

void parseElfHeaders(pid_t pid, long addr)
{
	long segAddr, memSize, cursor, got, plt, i, j;
	struct elf32 e32;
	struct elf64 e64;
	unsigned char *textSegment;
	unsigned char *dataSegment;
	unsigned char *dest;
	
	cursor = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

	if ((cursor & 0xff) == 0x7f && 
	    (cursor >>  8 & 0xff) == 'E' && 
	    (cursor >> 16 & 0xff) == 'L' && 
	    (cursor >> 24 & 0xff) == 'F') 
	{
		fprintf(stdout, "[*] - Magic number test [OK]\n");
		/* ==== 32 bits ==== */
		if ((cursor >> 32 & 0xff) == 1)
		{
			fprintf(stdout, "[*] - Elf 32-bit architecture\n");
			/* extract ELF header (Ehdr) */
			dest = calloc(sizeof(Elf32_Ehdr), 1);
			readProcessMemory(pid, sizeof(Elf32_Ehdr), addr, dest);
			e32.ehdr = (Elf32_Ehdr *)dest;
			/* extract Program header (Phdr) 
			 *
			 * We need to allocate e_phnum of Elf*_Phdr because as stated in 
			 * man elf, the Program headers is an array of structures, each
			 * describing a segment etc.. We use i as temporary variable to 
			 * store the number of segments.
			 *
			 */
			i = e32.ehdr->e_phnum * e32.ehdr->e_phentsize;
			dest = calloc(i, 1);
			readProcessMemory(pid, i, addr + e32.ehdr->e_phoff, dest);
			e32.phdr = (Elf32_Phdr *)dest;
			/* identify got/plt entries and patch them */
			for(i = 0; i < e32.ehdr->e_phnum; i++)
			{
				/* 
				 * man elf suggests PF_X | PF_W | PF_R to identify data segment
				 * but it seeems that data segments flags are only PF_R | PF_W
				 */ 
				if (e32.phdr[i].p_type  == PT_LOAD && 
				    e32.phdr[i].p_flags ==  (PF_X | PF_R))
				{
					segAddr = e32.phdr[i].p_vaddr + addr;
					memSize = e32.phdr[i].p_memsz;
					textSegment = calloc(memSize, 1);
					printf("[*] - Found .text @ 0x%lx\n", segAddr);
					readProcessMemory(pid, memSize, segAddr, textSegment);
				}
				if (e32.phdr[i].p_type  == PT_LOAD && 
				    e32.phdr[i].p_flags ==  (PF_W | PF_R))
				{
					segAddr = e32.phdr[i].p_vaddr + addr;
					memSize = e32.phdr[i].p_memsz;
					dataSegment = calloc(memSize, 1);
					printf("[*] - Found .data @ 0x%lx\n", segAddr);
					readProcessMemory(pid, memSize, segAddr, dataSegment);
					for(j = 0; j < e32.ehdr->e_phnum; j++)
					{
						if (e32.phdr[j].p_type == PT_DYNAMIC)
						{
							printf("[*] - Found .dynamic @ 0x%lx\n", addr + e32.phdr[j].p_vaddr);
							e32.dynSegment = (Elf32_Dyn *)&dataSegment[e32.phdr[j].p_vaddr - (segAddr - addr)];
							for(j = 0; e32.dynSegment[j].d_tag != DT_NULL; j++)
							{
								switch(e32.dynSegment[j].d_tag)
								{
									case DT_RELSZ:
										plt = addr + e32.ehdr->e_entry - e32.dynSegment[j].d_un.d_val;
										printf("[*] - Guess .plt @ 0x%lx\n", plt); 
										break;
									/* .got */
									case DT_PLTGOT:
										got = e32.dynSegment[j].d_un.d_ptr;
										printf("[*] - Found .got @ 0x%lx\n", got);
										break;
									/* size of .plt */
									case DT_PLTRELSZ:
										memSize = e32.dynSegment[j].d_un.d_val;
										printf("[*] - Number of PLT/GOT entries: %ld\n", memSize / sizeof(long));
										break;
								}
							}
							break;
						}
					}
					dest = calloc(memSize, 1);
					readProcessMemory(pid, memSize, got, dest);
					e32.got = dest;
					/* 
					 * Path GOT and ignore GOT[0], GOT[1] and 
					 * GOT[2], code is sooo ugly. After being 
					 * stuck on finding PLT stub address I do
					 * not find an elegant way to iterate the
					 * GOT table, each entry is 0x10 long and
					 * we're using that, sorry @ll.
					 *
					 * */
					for(j = 3; j < memSize/sizeof(long)+3; j++)
					{
						/* TODO : write this on dataSegment, push 
						 * modification to restore original ELF on 
						 * the disk.
						 */
						printf("[*] - GOT[%ld] :: [@%p] - %x\n",j , (int*)e32.got + j, *((int *)e32.got + j));
						printf("[*] - Patch %x with %x\n", *((int *)e32.got + j), plt + 0x6 + (0x10 * (j - 3)));
					}
				}
			}
			freeBobby(5, e32.ehdr, e32.phdr, textSegment, dataSegment, dest);
		}
		/* ==== 64 bits ==== */
		if ((cursor >> 32 & 0xff) == 2)
		{
			fprintf(stdout, "[*] - Elf 64-bit architecture\n");
			/* extract ELF header (Ehdr) */
			dest = calloc(sizeof(Elf64_Ehdr), 1);
			readProcessMemory(pid, sizeof(Elf64_Ehdr), addr, dest);
			e64.ehdr = (Elf64_Ehdr *)dest;
			i = e64.ehdr->e_phnum;
			/* extract Program header (Phdr) 
			 *
			 * We need to allocate e_phnum of Elf*_Phdr because as stated in 
			 * man elf, the Program headers is an array of structures, each
			 * describing a segment etc.. We use i as temporary variable to 
			 * store the number of segments.
			 *
			 */
			dest = calloc(sizeof(Elf64_Phdr) * i, 1);
			readProcessMemory(pid, sizeof(Elf64_Phdr) * i, addr + e64.ehdr->e_phoff, dest);
			e64.phdr = (Elf64_Phdr *)dest;
			for(i = 0; i < e64.ehdr->e_phnum; i++)
			{
				/* 
				 * man elf suggests PF_X | PF_W | PF_R to identify data segment
				 * but it seeems that data segments flags are only PF_R | PF_W
				 */ 
				if (e64.phdr[i].p_type  == PT_LOAD && 
				    e64.phdr[i].p_flags ==  (PF_X | PF_R))
					printf("Found .text @ %lx\n", addr + e64.phdr[i].p_vaddr);
				if (e64.phdr[i].p_type  == PT_LOAD && 
				    e64.phdr[i].p_flags ==  (PF_W | PF_R))
					printf("Found .data @ %lx\n", addr + e64.phdr[i].p_vaddr);
				if (e64.phdr[i].p_type  == PT_DYNAMIC)
					printf("Found .dyna @ %lx\n", addr + e64.phdr[i].p_vaddr);
			}
			freeBobby(2, e64.ehdr, e64.phdr);
		}
	} else
	{
		perror("Failed magic number test\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		exit(EXIT_FAILURE);
	}
}

/* 
 * -r--r--r-- 1 root root 0 mars   2 09:09 /proc/1/maps 
 *
 * 55f46165d000-55f461666000 r--p 00000000 08:02 393991 /usr/bin/dbus-daemon
 * 55f461666000-55f461688000 r-xp 00009000 08:02 393991 /usr/bin/dbus-daemon
 * 55f461688000-55f461696000 r--p 0002b000 08:02 393991 /usr/bin/dbus-daemon
 * 55f461696000-55f461698000 r--p 00038000 08:02 393991 /usr/bin/dbus-daemon
 * 55f461698000-55f461699000 rw-p 0003a000 08:02 393991 /usr/bin/dbus-daemon
 * [...]
 *
 *  */

long extractBaseAddress(char *mapsPath)
{
	FILE *fd;
	/* 64 bit address, hexadecimal format plus trailing '-' to prevent overflow from getdelim */ 
	char *baseAddress = calloc(strlen("0000000000000000-") + 1, sizeof(char));
	size_t lineSize = sizeof(baseAddress);
	long r;

	if ((fd = fopen(mapsPath, "r")) == NULL)
	{
		fprintf(stderr, "can not open %s\n", mapsPath);
		exit(EXIT_FAILURE);
	}
	if (getdelim(&baseAddress, &lineSize, '-', fd) == -1)
	{
		perror("can not extract base address");
		exit(EXIT_FAILURE);
	}
	/* delete trailing '-' */
	baseAddress[strlen(baseAddress) - 1] = '\0';
	r = strtol(baseAddress, NULL, 16);
	free(baseAddress);
	fclose(fd);

	return r;
}

/* -rw-r--r-- 1 root root 0 mars   2 09:09 /proc/sys/kernel/pid_max */
pid_t pidMax(void)
{
	FILE *fd;
	pid_t pidM;

	if ((fd = fopen("/proc/sys/kernel/pid_max", "r")) == NULL)
	{
		perror("can not open /proc/sys/kernel/pid_max\n");
		exit(EXIT_FAILURE);
	}
	fscanf(fd,"%d",&pidM);
	fclose(fd);

	return pidM;
}	

void freeBobby(int count, ...)
{
	va_list ap;

	va_start(ap, count);
	while(count--)
		free(va_arg(ap, void *));
	va_end(ap);
}
