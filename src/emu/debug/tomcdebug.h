
// dump instrumented disassembly
bool debug_tomcdasm(running_machine &machine,address_space &space,const char *filename,uint64_t address,uint64_t length);

// our instruction hook (for compiling instruction callers, etc)
void tomc_instruction_hook(device_debug &debug, running_machine &machine, offs_t curpc, bool implicit);
