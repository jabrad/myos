#include <stdio.h>

#include <kernel/tty.h>
#include <kernel/paging.h>
#include <stdint.h>
#include <string.h>


uint32_t page_directory[1024] __attribute__((aligned(4096)));
uint32_t first_page_table[1024] __attribute__((aligned(4096)));

void paging_initialize() {
	//set each entry to not present
	int i;
	for(i = 0; i < 1024; i++)
	{
		// This sets the following flags to the pages:
		//   Supervisor: Only kernel-mode can access them
		//   Write Enabled: It can be both read from and written to
		//   Not Present: The page table is not present
		page_directory[i] = 0x00000002;
	}

	//we will fill all 1024 entries in the table, mapping 4 megabytes
	for(i = 0; i < 1024; i++)
	{
		// As the address is page aligned, it will always leave 12 bits zeroed.
		// Those bits are used by the attributes ;)
		first_page_table[i] = (i * 0x1000) | 3; // attributes: supervisor level, read/write, present.
	}

	// attributes: supervisor level, read/write, present
	page_directory[0] = ((uint32_t)first_page_table) | 3;

	loadPageDirectory(page_directory);
}

struct AtaDriverData {
	uint32_t ptrlen;
	uint32_t stLBA;
	uint16_t tf;
	uint16_t dcr;
	uint8_t sbits;
};

struct AtaDriverData ata_driver_data;

void ata_lba_read(uint32_t lba, uint16_t *buffer, uint32_t sector_count, struct AtaDriverData *driver_data);

#define SECTOR_SIZE 512

uint8_t sector_data[SECTOR_SIZE];
uint8_t partition_entry[16];

#define PARTITION_ENTRY_1 0x1BE
#define PARTITION_ENTRY_2 0x1CE
#define PARTITION_ENTRY_3 0x1DE
#define PARTITION_ENTRY_4 0x1EE

#define PARTITION_ENTRY_ATTR      0x0
#define PARTITION_ENTRY_CHS_START 0x1
#define PARTITION_ENTRY_TYPE      0x4
#define PARTITION_ENTRY_CHS_LAST  0x5
#define PARTITION_ENTRY_LBA       0x8
#define PARTITION_ENTRY_SECTORS   0xC

#define EXT_SUPERBLOCK_TOTAL_BLOCKS 8
#define EXT_SUPERBLOCK_BLOCK_SIZE 24
#define EXT_SUPERBLOCK_BLOCKS_PER_GROUP 32
#define EXT_SUPERBLOCK_INODES_PER_GROUP 40
#define EXT_SUPERBLOCK_INODE_SIZE 88

#define EXT_GROUP_DESCRIPTOR_TABLE_ENTRY_SIZE 32
#define EXT_GROUP_DESCRIPTOR_INODE_TABLE 8

#define EXT_INODE_SIZE_LSB 4
#define EXT_INODE_DIRECT_BLOCK_0 40


struct ExtParams {
	uint32_t base_lba;
	uint32_t total_blocks;
	uint32_t block_size;
	uint32_t blocks_per_group;
	uint32_t inodes_per_group;
	uint16_t inode_size;
};

uint8_t group_desc_table_data[4096]; // TODO: should be allocated dynamically
uint8_t block_data[4096];// TODO: should be allocated dynamically

void read_block(struct ExtParams *params, uint32_t block, uint8_t *data) {
	uint32_t sectors = params->block_size / SECTOR_SIZE;

	uint32_t block_lba = block * sectors;

	ata_lba_read(block_lba, data, sectors, &ata_driver_data);
}

uint32_t read_inode_content(struct ExtParams *params, uint32_t inode, uint8_t *data) {
	uint32_t group = (inode - 1) / params->inodes_per_group;
	uint32_t index = (inode - 1) % params->inodes_per_group;

	uint8_t *table_entry_ptr = &group_desc_table_data[group * EXT_GROUP_DESCRIPTOR_TABLE_ENTRY_SIZE];
	uint32_t inode_table_start_block = ((uint32_t *)table_entry_ptr)[EXT_GROUP_DESCRIPTOR_INODE_TABLE / 4];

	uint32_t inode_table_block_offset = (index * params->inode_size) / params->block_size;
	uint32_t inode_table_inode_index  = ((index * params->inode_size) % params->block_size) / params->inode_size;

	read_block(params, inode_table_start_block + inode_table_block_offset, data);

	uint8_t *inode_fields_ptr = &data[inode_table_inode_index * params->inode_size];
	uint32_t inode_size = ((uint32_t *)inode_fields_ptr)[EXT_INODE_SIZE_LSB / 4];
	uint32_t inode_direct_block_0 = ((uint32_t *)inode_fields_ptr)[EXT_INODE_DIRECT_BLOCK_0 / 4];

	read_block(params, inode_direct_block_0, data);

	return inode_size;
}

struct DirectoryEntry {
	uint32_t inode;
	uint16_t length;
	uint8_t nameLengthLSB;
	uint8_t type;
};

uint32_t getFileInode(struct ExtParams *params, uint32_t dir_inode, char *name) {
	uint32_t file_inode = 0;
	size_t nameLen = strlen(name);

	read_inode_content(params, 2, block_data);

	struct DirectoryEntry entry = *((struct DirectoryEntry *)block_data);

	uint32_t offset = 0;

	while (offset != params->block_size && entry.length != 0) {
		if (entry.nameLengthLSB == nameLen) {
			char *entryName = block_data + offset + sizeof(struct DirectoryEntry);

			if (memcmp(entryName, name, nameLen) == 0) {
				file_inode = entry.inode;

				break;
			}
		}

		offset += entry.length;
		entry = *((struct DirectoryEntry *)(block_data + offset));
	}

	return file_inode;
}

void kernel_main(void) {
	// Init paging
	paging_initialize();
	enablePaging();

	// Init terminal
	terminal_initialize();

	// Init ATA driver
	ata_driver_data.ptrlen = 2;
	ata_driver_data.stLBA = 0;
	ata_driver_data.tf = 0x1F0;
	ata_driver_data.dcr = 0x3F6;
	ata_driver_data.sbits = 0xe0;

	// Read MBR sector
	ata_lba_read(0, sector_data, 1, &ata_driver_data);

	// Read first partition's entry
	memcpy(partition_entry, &sector_data[PARTITION_ENTRY_1], 16);
	uint32_t partition_1_lba = ((uint32_t *)partition_entry)[PARTITION_ENTRY_LBA / 4];
	uint32_t partition_1_sectors = ((uint32_t *)partition_entry)[PARTITION_ENTRY_SECTORS / 4];

	// Update ATA driver parameters
	ata_driver_data.ptrlen = partition_1_sectors;
	ata_driver_data.stLBA = partition_1_lba;

	// Read ext superblock
	uint32_t superblock_lba = 2; // Sector size is 512, superblock starts 1024B from the start, thus the "2"
	ata_lba_read(superblock_lba, sector_data, 1, &ata_driver_data);

	// Read ext parameters
	struct ExtParams ext_params = {
		.base_lba = partition_1_lba,
		.total_blocks = ((uint32_t *)sector_data)[EXT_SUPERBLOCK_TOTAL_BLOCKS / 4],
		.block_size = 1024 << ((uint32_t *)sector_data)[EXT_SUPERBLOCK_BLOCK_SIZE / 4],
		.blocks_per_group = ((uint32_t *)sector_data)[EXT_SUPERBLOCK_BLOCKS_PER_GROUP / 4],
		.inodes_per_group = ((uint32_t *)sector_data)[EXT_SUPERBLOCK_INODES_PER_GROUP / 4],
		.inode_size = ((uint16_t *)sector_data)[EXT_SUPERBLOCK_INODE_SIZE / 2],
	};

	// Read Block Group Descriptor Table
	uint32_t superblock_block = 2048 / ext_params.block_size; // TODO: should be ceil(2048 / ext_params.block_size) - 1
	uint32_t group_desc_table_block = superblock_block + 1;
	read_block(&ext_params, group_desc_table_block, group_desc_table_data);

	// Read file

	char fileToRead[] = "kubek";
	char stringBuffer[257];

	// Search for the file's inode in the root directory
	uint32_t kubek_inode = getFileInode(&ext_params, 2, fileToRead);
	
	if (kubek_inode != 0) {
		// Read file content
		uint32_t content_size = read_inode_content(&ext_params, kubek_inode, block_data);

		size_t acceptableStringLen = content_size <= 256 ? content_size : 256;

		memcpy(stringBuffer, block_data, acceptableStringLen);
		stringBuffer[acceptableStringLen] = '\0';

		printf("%s", stringBuffer);
	}
	else {
		printf("File \"%s\" doesn't exist", fileToRead);
	}
}
