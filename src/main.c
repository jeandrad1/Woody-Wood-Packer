#include "woody-woodpacker.h"

int	main(int argc, char **argv)
{
	int				fd;
	size_t			file_size;
	size_t			total_size;
	void			*file;
	unsigned char	key[KEY_SIZE];
	uint64_t		orig_entry;
	char			*file_path = NULL;
	char			*key_str = NULL;

	if (argc != 2 && argc != 4)
		return (printf("Usage: ./woody_woodpacker <elf file> [-k key]\n"), EXIT_FAILURE);

	file_path = argv[1];

	if (argc == 4)
	{
		if (strcmp(argv[2], "-k") == 0)
			key_str = argv[3];
		else
			return (printf("Usage: ./woody_woodpacker <elf file> [-k key]\n"), EXIT_FAILURE);
	}

	fd = open(file_path, O_RDONLY);
	if (fd < 0)
		return (perror("Error opening file"), EXIT_FAILURE);
	file_size = get_file_size(fd);
	if (file_size == 0)
		return (perror("Empty file"), EXIT_FAILURE);
	/* Reservar espacio extra para el padding de alineación + el stub */
	total_size = ((file_size + 0xFFF) & ~(size_t)0xFFF) + STUB_SIZE;
	file = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (file == MAP_FAILED)
		return (perror("mmap failed"), close(fd), EXIT_FAILURE);
	if (read(fd, file, file_size) != (ssize_t)file_size)
		return (perror("read failed"),
			munmap(file, total_size), close(fd), EXIT_FAILURE);
	if (parse_elf64(file, file_size) != 0)
		return (munmap(file, total_size), close(fd), EXIT_FAILURE);
	if (key_str)
	{
		if (parse_hex_key(key_str, key, KEY_SIZE) != 0)
			return (munmap(file, total_size), close(fd), EXIT_FAILURE);
	}
	else
		generate_random_key(key, KEY_SIZE);
	print_key(key, KEY_SIZE);
	/* Guardar entry point original antes de modificar el ELF */
	orig_entry = ((Elf64_Ehdr *)file)->e_entry;
	/* Cifrar segmento ejecutable con XOR */
	encrypt_segment(file, file_size, key);
	/* Inyectar stub y redirigir entry point */
	if (inject_stub(file, file_size, key, orig_entry) != 0)
		return (munmap(file, total_size), close(fd), EXIT_FAILURE);
	/* Escribir binario infectado */
	if (write_woody(file, file_size) != 0)
		return (munmap(file, total_size), close(fd), EXIT_FAILURE);
	return (close(fd), munmap(file, total_size), 0);
}