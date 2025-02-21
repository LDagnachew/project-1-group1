#include <inc/lib.h>
#include <inc/vmx.h>
#include <inc/elf.h>
#include <inc/ept.h>
#include <inc/stdio.h>

#define GUEST_KERN "/vmm/kernel"
#define GUEST_BOOT "/vmm/boot"

#define JOS_ENTRY 0x7000

// Map a region of file fd into the guest at guest physical address gpa.
// The file region to map should start at fileoffset and be length filesz.
// The region to map in the guest should be memsz.  The region can span multiple pages.
//
// Return 0 on success, <0 on failure.
//
// Hint: Call sys_ept_map() for mapping page. 
static int
map_in_guest( envid_t guest, uintptr_t gpa, size_t memsz, 
	      int fd, size_t filesz, off_t fileoffset ) {
    
	int r;
    void *srcva;
    size_t i;
    uintptr_t gpa_start = (uintptr_t)gpa;
    uintptr_t gpa_end = gpa_start + filesz;

    //seek once to get to the fileoffset, or return if error.
    if((r = seek(fd, fileoffset)) < 0) {
        return r;
    }
    
    // Iterate over each page in the segment
    for (i = 0; i < memsz; i += PGSIZE) {
        // Use UTEMP for temporary page mapping
        srcva = UTEMP; // Is this right ??
        if ((r = sys_page_alloc(0, srcva, PTE_P | PTE_U | PTE_W)) < 0) {
            cprintf("1");
            return r; 
        }

        size_t bytes_remaining_file = 0;
        if (i < filesz) {
            bytes_remaining_file = filesz - i;
        }
        
        size_t size_to_read = (bytes_remaining_file < PGSIZE) ? bytes_remaining_file : PGSIZE;
        
        // Read data from file if needed
        if (size_to_read > 0) {
            if ((r = readn(fd, srcva, size_to_read)) != size_to_read) {
                sys_page_unmap(0, srcva);
                return -E_INVAL;
            }
        }
        
        // Zero the rest of the page if needed
        if (size_to_read < PGSIZE) {
            memset((char*)srcva + size_to_read, 0, PGSIZE - size_to_read);
        }

        // Map the page into the guest's physical memory using sys_ept_map
        //cprintf("Mapping HVA %p to GPA %p\n", srcva, (void *)(gpa_start + i));
        if ((r = sys_ept_map(sys_getenvid(), srcva, guest, (void *)(gpa_start + i), __EPTE_READ | __EPTE_WRITE | __EPTE_EXEC)) < 0) {
            sys_page_unmap(0, srcva);
            return r;
        }
        
        sys_page_unmap(0, srcva);
    }

    return 0; // Success
} 

// Read the ELF headers of kernel file specified by fname,
// mapping all valid segments into guest physical memory as appropriate.
//
// Return 0 on success, <0 on error
//
// Hint: compare with ELF parsing in env.c, and use map_in_guest for each segment.
static int copy_guest_kern_gpa(envid_t guest, char* fname) {
    int fd;
    struct Elf *elf;
    struct Proghdr *ph, *eph;
    
    // Start by locating the kernel file
    if ((fd = open(fname, O_RDONLY)) < 0) {
        return -E_BAD_PATH;
    }

    // Malloc the appropriate size. 
    elf = malloc(PGSIZE);
    if (!elf) {
        close(fd);
        return -E_NO_MEM;
    }

    // Read ELF header, make sure we handle event of failure
    if (readn(fd, elf, sizeof(struct Elf)) != sizeof(struct Elf)) {
        free(elf);
        close(fd);
        return -E_NOT_EXEC;
    }


    // Check ELF header
    if(elf->e_magic!=ELF_MAGIC) {
        return -E_NOT_EXEC;
    }

    // We need to read the program headers, but there may be an offset because of padding.
    if (seek(fd, elf->e_phoff) < 0) {  
        free(elf);
        close(fd);
        return -E_NOT_EXEC;
    }
    

    size_t ph_size = elf->e_phnum * sizeof(struct Proghdr);
    ph = malloc(ph_size);  // Allocate space for all program headers
    if (!ph) {
        free(elf);
        close(fd);
        return -E_NO_MEM;
    }

    // Verify that we have read every part of the program header BEFORE we proceed to do anything.
    if (readn(fd, ph, ph_size) != ph_size) {
        free(ph);
        free(elf);
        close(fd);
        return -E_NOT_EXEC;
    }
    
    eph = ph + elf->e_phnum;

    // Iterate over program headers and map segments (same as env.c)
    struct Proghdr *p;
    for (p = ph; p < eph; p++) {
        if (p->p_type == ELF_PROG_LOAD) {
            // Convert guest virtual address (p_va) to guest physical address (gpa)
            uintptr_t gpa = p->p_pa;
    
            // Debugging: Check if GPA is now reasonable
            cprintf("Mapping p_va=0x%lx to gpa=0x%lx\n", p->p_va, gpa);
    
            // Now pass the corrected gpa to map_in_guest()
            if (map_in_guest(guest, p->p_pa, p->p_memsz, fd, p->p_filesz, p->p_offset) < 0) {
                free(ph);
                free(elf);
                close(fd);
                return -E_NO_MEM;
            }
        }
    }
    

    free(elf);
    close(fd);
    return 0;
}

void
umain(int argc, char **argv) {
	int ret;
	envid_t guest;
	char filename_buffer[50];	//buffer to save the path 
	int vmdisk_number;
	int r;
	if ((ret = sys_env_mkguest( GUEST_MEM_SZ, JOS_ENTRY )) < 0) {
		cprintf("Error creating a guest OS env: %e\n", ret );
		exit();
	}
	guest = ret;

	// Copy the guest kernel code into guest phys mem.
	if((ret = copy_guest_kern_gpa(guest, GUEST_KERN)) < 0) {
		cprintf("Error copying page into the guest - %d\n.", ret);
		exit();
	}

	// Now copy the bootloader.
	int fd;
	if ((fd = open( GUEST_BOOT, O_RDONLY)) < 0 ) {
		cprintf("open %s for read: %e\n", GUEST_BOOT, fd );
		exit();
	}

	// sizeof(bootloader) < 512.
	if ((ret = map_in_guest(guest, JOS_ENTRY, 512, fd, 512, 0)) < 0) {
		cprintf("Error mapping bootloader into the guest - %d\n.", ret);
		exit();
	}
#ifndef VMM_GUEST	
	sys_vmx_incr_vmdisk_number();	//increase the vmdisk number
	//create a new guest disk image
	
	vmdisk_number = sys_vmx_get_vmdisk_number();
	snprintf(filename_buffer, 50, "/vmm/fs%d.img", vmdisk_number);
	
	cprintf("Creating a new virtual HDD at /vmm/fs%d.img\n", vmdisk_number);
        r = copy("vmm/clean-fs.img", filename_buffer);
        
        if (r < 0) {
        	cprintf("Create new virtual HDD failed: %e\n", r);
        	exit();
        }
        
        cprintf("Create VHD finished\n");
#endif
	// Mark the guest as runnable.
	sys_env_set_status(guest, ENV_RUNNABLE);
	wait(guest);
}


