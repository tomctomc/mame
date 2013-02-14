
/**
 * experimental instrumentation of disassembly while the emulator is running
 */
#include "emu.h"
#include "emuopts.h"
#include "debugcon.h"
#include "debugcpu.h"
#include "debugger.h"
#include <set>
#include <vector>
#include <map>

static const int MEMORY_MAX = 128*1024;

typedef uint8_t MEMORYTYPE;
static const MEMORYTYPE MEMORYTYPE_UNKNOWN        = 0;
static const MEMORYTYPE MEMORYTYPE_INSTRUCTION    = 1;
static const MEMORYTYPE MEMORYTYPE_MIDINSTRUCTION = 2;

static MEMORYTYPE memory[MEMORY_MAX];
static uint32_t execution_counter = 0;

class INSTRUCTION {
    public:
        offs_t                address;
        uint32_t                execution_order;
        uint32_t                length;
        uint32_t                dasmresult; // includes debugger flags (like step out, step over)
        uint32_t                flags;      // out flags (new entry point, terminator, conditional)
        std::string               operatr;
        std::string               operand;
        std::string               hexbytes;
        offs_t                entry_caller;
        bool                  implicit;
        std::map<offs_t,int>  caller_counts;
};

typedef enum {
    LABEL_JMP,
    LABEL_SUB,
    LABEL_ENT
} LABEL_TYPE;

static std::map<offs_t,INSTRUCTION> instructions;
static std::map<offs_t,LABEL_TYPE>  labels;
static std::set<offs_t>             mid_instruction_addresses;
static std::map<offs_t,offs_t>      implicit_code;

static char const   *byte_declaration = (char const *) "byte";
static char const *equate_declaration = (char const *) "=";

static offs_t lastpc = -1;
static bool firstTimeSetup = true;

/**
 * this instruction's operand specifies a new entry point (execution address)
 * for example: any jump, any branch, or any jsr
 */
#define IF_NEWENTRYPOINT 0x01

/**
 * this instruction prohibits the next sequential address from executing
 * for example: an unconditional jump or return
 */
#define IF_TERMINATOR    0x02

/**
 * this instruction is a conditional
 * for example: any conditional jump or branch
 */
#define IF_CONDITIONAL   0x04

/**
 * this instruction is a return to a previous execution address
 * for example: any rts or rti
 */
#define IF_RETURN        0x08

/**
 * this instruction begins or ends a subroutine
 * for example: any bsr, jsr, or rts
 */
#define IF_SUBROUTINE    0x10

/**
 * instruction "types" (just prepackaged instruction flag combinations for static initializers)
 */
#define IT_CALL_SUBROUTINE    ( IF_NEWENTRYPOINT                                               | IF_SUBROUTINE )
#define IT_RETURN_SUBROUTINE  (                    IF_TERMINATOR    | IF_RETURN                | IF_SUBROUTINE )
#define IT_RETURN_INTERRUPT   (                    IF_TERMINATOR    | IF_RETURN                                )
#define IT_JUMP               ( IF_NEWENTRYPOINT | IF_TERMINATOR                                               )
#define IT_JUMP_CONDITIONAL   ( IF_NEWENTRYPOINT |                              IF_CONDITIONAL                 )

struct instruction_flag {
    const char   *operatr;
    const uint32_t  flags;
};
static struct instruction_flag instruction_flags[] = {

    { "jsr",   IT_CALL_SUBROUTINE   },
    { "bsr",   IT_CALL_SUBROUTINE   },
    { "lbsr",  IT_CALL_SUBROUTINE   },

    { "rtn",   IT_RETURN_SUBROUTINE },
    { "rts",   IT_RETURN_SUBROUTINE },

    { "rti",   IT_RETURN_INTERRUPT  },

    { "jmp",   IT_JUMP              },
    { "bra",   IT_JUMP              },
    { "lbra",  IT_JUMP              },

    { "bcc",   IT_JUMP_CONDITIONAL  },
    { "bcs",   IT_JUMP_CONDITIONAL  },
    { "beq",   IT_JUMP_CONDITIONAL  },
    { "bge",   IT_JUMP_CONDITIONAL  },
    { "bgt",   IT_JUMP_CONDITIONAL  },
    { "bhi",   IT_JUMP_CONDITIONAL  },
    { "bhs",   IT_JUMP_CONDITIONAL  },
    { "ble",   IT_JUMP_CONDITIONAL  },
    { "blo",   IT_JUMP_CONDITIONAL  },
    { "bls",   IT_JUMP_CONDITIONAL  },
    { "blt",   IT_JUMP_CONDITIONAL  },
    { "bmi",   IT_JUMP_CONDITIONAL  },
    { "bne",   IT_JUMP_CONDITIONAL  },
    { "bpl",   IT_JUMP_CONDITIONAL  },
    { "bra",   IT_JUMP_CONDITIONAL  },
    { "bvc",   IT_JUMP_CONDITIONAL  },
    { "bvs",   IT_JUMP_CONDITIONAL  },
    { "lbcc",  IT_JUMP_CONDITIONAL  },
    { "lbcs",  IT_JUMP_CONDITIONAL  },
    { "lbeq",  IT_JUMP_CONDITIONAL  },
    { "lbge",  IT_JUMP_CONDITIONAL  },
    { "lbgt",  IT_JUMP_CONDITIONAL  },
    { "lbhi",  IT_JUMP_CONDITIONAL  },
    { "lbhs",  IT_JUMP_CONDITIONAL  },
    { "lble",  IT_JUMP_CONDITIONAL  },
    { "lblo",  IT_JUMP_CONDITIONAL  },
    { "lbls",  IT_JUMP_CONDITIONAL  },
    { "lblt",  IT_JUMP_CONDITIONAL  },
    { "lbmi",  IT_JUMP_CONDITIONAL  },
    { "lbne",  IT_JUMP_CONDITIONAL  },
    { "lbpl",  IT_JUMP_CONDITIONAL  },
    { "lbra",  IT_JUMP_CONDITIONAL  },
    { "lbvc",  IT_JUMP_CONDITIONAL  },
    { "lbvs",  IT_JUMP_CONDITIONAL  },

    { "LIST_TERMINATOR", 0 } // bogus list terminator
};

static const int DASM_PRINT_LABEL_SIZE    = 16-1;
static const int DASM_PRINT_OPERATOR_SIZE = 12-1;
static const int DASM_PRINT_OPERAND_SIZE  = 16-1;
static const int NINSTRUCTION_FLAGS = sizeof( instruction_flags ) / sizeof( struct instruction_flag );

static const int n_address_chars          =  4;
static const int max_instruction_length   =  4; // bytes

static device_debug *tuck_debug;
static const offs_t BADADDRESS = -1000000;

offs_t tomc_parse_target_address( std::string operand )
{
    offs_t address = (offs_t) 0;

    // new entry point
    const char *s = operand.c_str();
    //TOMCXXX THIS ONLY WORKS FOR 16 BIT ABSOLUTE ADDRESSES!!!
    if( s[0] == '$' ) {
        if( isxdigit(s[1]) ) {
            if( isxdigit(s[2]) ) {
                if( isxdigit(s[3]) ) {
                    if( isxdigit(s[4]) ) {
                        int val;
                        sscanf( s+1, "%04X", &val );
                        address = val;
                    }
                }
            }
        }
    }

    return( address );
}

static std::string no_label;
static std::string reused_label;
std::string &get_label( offs_t address )
{
    std::string &label = reused_label;

    if( labels.find(address) == labels.end() ) {
        return( no_label );
    }
    
    LABEL_TYPE label_type = labels[address];

    const char *prefix = "xxx_";
    switch( label_type ) {
        case LABEL_JMP: prefix = "JMP_"; break;
        case LABEL_SUB: prefix = "SUB_"; break;
        case LABEL_ENT: prefix = "ENT_"; break;
    }

    static char tmpbuf[1024+1];
    sprintf( tmpbuf, "%s%0*x", prefix, n_address_chars, (int) address );
    label = tmpbuf;

    return( label );
}

void assign_label( const LABEL_TYPE label_type, offs_t address )
{
    if( labels.find(address) != labels.end() ) {
        if( labels[address] > label_type ) {
            // can only "upgrade" label types (jmp->sub->ent)
            return;
        }
    }

    labels[address] = label_type;
}

void mark_implicit_code( offs_t address, offs_t caller )
{
    implicit_code[address] = caller;
}

void fprintf_instruction( FILE *f, INSTRUCTION &instruction, bool brief )
{
    if( brief ) {
        fprintf( f, "%s %s ; [%0*x]",
            instruction.operatr.c_str(),
            instruction.operand.c_str(),
            n_address_chars,
            instruction.address );
        return;
    }

    fprintf( f, "%-*s %-*s %-*s ;",
        DASM_PRINT_LABEL_SIZE,    get_label( instruction.address ).c_str(),
        DASM_PRINT_OPERATOR_SIZE, instruction.operatr.c_str(),
        DASM_PRINT_OPERAND_SIZE,  instruction.operand.c_str() );

    fprintf( f, " [%0*x] %-*s",
        n_address_chars,          instruction.address,
        max_instruction_length*3, instruction.hexbytes.c_str() );

    fprintf( f, " (%5d)", instruction.execution_order);

    if( instruction.implicit ) {
        fprintf( f, " (IMP_%5d)", instruction.execution_order );
    }

    if( instruction.entry_caller != BADADDRESS ) {
        fprintf( f, " (ENT " );
        fprintf_instruction( f, instructions[instruction.entry_caller], true );
        fprintf( f, ")" );
    }

    std::map<offs_t,int>::const_iterator caller;
    for( caller = instruction.caller_counts.begin(); caller != instruction.caller_counts.end(); ++caller ) {
        const char *note = "";
        INSTRUCTION &calling_instruction = instructions[caller->first];
        uint32_t flags = calling_instruction.flags;
        if( flags & IF_RETURN ) {
            if( flags & IF_SUBROUTINE ) {
                note = "rts:";
            }
            else {
                note = "rti:";
            }
        }
        if( calling_instruction.address + calling_instruction.length == instruction.address ) {
            note = "seq:";
        }
        if( note[0] == '\0' ) {
            fprintf( f, " [" );
            fprintf_instruction( f, calling_instruction, true );
            fprintf( f, ":%3d]", caller->second );
        }
    }
}

void trace_all_implicit(running_machine &machine, uint64_t address,uint64_t length)
{
    if( tuck_debug ) {
        bool keep_going = true;
        while( keep_going ) {
            keep_going = false;
            std::map<offs_t,offs_t>::const_iterator itr;
            for( itr = implicit_code.begin(); itr != implicit_code.end(); itr++ ) {
                printf( "TOMCXXX: processing implicit %04x\n", (int) itr->first );
                if( itr->first >= address && itr->first < address+length ) { // only if in range...
                    if( memory[itr->first] == MEMORYTYPE_UNKNOWN ) {
                        lastpc = itr->second;
                        offs_t curpc = itr->first;
                        while( memory[curpc] == MEMORYTYPE_UNKNOWN ) {
                            if( curpc < address || curpc >= address+length ) {
                                // out of requested dasm range
                                break;
                            }
                            tomc_instruction_hook(*tuck_debug, machine,curpc,true);
                            INSTRUCTION &instruction = instructions[curpc];
                            curpc += instruction.length;
                            if( instruction.flags & IF_TERMINATOR ) {
                                break;
                            }
                            if( ( instruction.operatr.find( "PUL" ) ||
                                  instruction.operatr.find( "pul" ) ) &&
                                ( instruction.operand.find( "PC" ) ||
                                  instruction.operand.find( "pc" ) ) ) {
                                // on the 6809, a "PUL" operation that also pulls the PC register is the same as a return
                                break;
                            }
                        }
                        keep_going = true;
                        break;
                    }
                }
            }
        }
    }
}

void label_upgrade_sub(uint64_t address,uint64_t length)
{
    std::map<offs_t,INSTRUCTION>::iterator itr;

    for( itr = instructions.begin(); itr != instructions.end(); itr++ ) {
        INSTRUCTION &instruction = itr->second;
        if( ( instruction.flags & IT_CALL_SUBROUTINE ) == IT_CALL_SUBROUTINE ) {
            offs_t target_address = tomc_parse_target_address( instruction.operand );
            if( target_address ) {
                assign_label( LABEL_SUB, target_address );
            }
        }
    }
}

void label_upgrade_ent(uint64_t address,uint64_t length)
{
    std::map<offs_t,INSTRUCTION>::iterator itr;

    for( itr = instructions.begin(); itr != instructions.end(); itr++ ) {
        if( itr->first >=  address         &&
            itr->first <  (address+length) ) {
            INSTRUCTION &instruction = itr->second;
            std::map<offs_t,int>::const_iterator caller;
            for( caller = instruction.caller_counts.begin(); caller != instruction.caller_counts.end(); ++caller ) {
                if( caller->first <   address         ||
                    caller->first >= (address+length) ) {
                    // if caller is outside disassembly range, identify this as an "external entry" point
                    instruction.entry_caller = caller->first;
                    assign_label( LABEL_ENT, instruction.address );
                }
            }
        }
    }
}

void remove_mid_instruction_labels()
{
    std::set<offs_t>::iterator itr;

    for( itr = mid_instruction_addresses.begin(); itr != mid_instruction_addresses.end(); itr++ ) {
        fprintf( stderr, "warning: removing label due to mid-instruction %08x\n", *itr );
        labels.erase(*itr);
    }
}

void change_to_use_labels()
{
    std::map<offs_t,INSTRUCTION>::iterator itr;

    for( itr = instructions.begin(); itr != instructions.end(); itr++ ) {
        INSTRUCTION &instruction = itr->second;
        offs_t target_address = tomc_parse_target_address( instruction.operand );
        if( target_address ) {
            std::string label = get_label( target_address );
            if( label.c_str()[0] != '\0' ) {
                instruction.operand = get_label( target_address );
            }
        }
    }
}

void define_out_of_range_labels(FILE *f, uint64_t address,uint64_t length)
{
    // for any labels we generated outside the range we are disassembling, insert equates.
    std::map<offs_t,LABEL_TYPE>::iterator itr;

    int start = address;
    int end   = address+length;
    for( itr = labels.begin(); itr != labels.end(); itr++ ) {
        offs_t pc = itr->first;
        if( pc < start || pc >= end ) {
            fprintf( f, "%-*s %-*s $%04x\n",
                DASM_PRINT_LABEL_SIZE,    get_label(pc).c_str(),
                DASM_PRINT_OPERATOR_SIZE, equate_declaration,
                (int) pc );
        }
    }
}

bool debug_tomcdasm(running_machine &machine,address_space &space,const char *filename,uint64_t address,uint64_t length)
{
    trace_all_implicit(machine, address, length );
    label_upgrade_sub( address, length );
    label_upgrade_ent( address, length );
    remove_mid_instruction_labels();
    change_to_use_labels();

    FILE *f = fopen(filename, "wb");

    if (!f)
    {
        fprintf(stderr, "Error opening file '%s' for writing\n", filename );
        return false;
    }

    fprintf( f, "\n" );
    define_out_of_range_labels(f,address,length);
    fprintf( f, "\n" );

    fprintf( f, "%-*s %-*s $%0*lx%-*s ; \n",
        DASM_PRINT_LABEL_SIZE,                      "",
        DASM_PRINT_OPERATOR_SIZE,                   "org",
        n_address_chars,                            (long unsigned) address,
        DASM_PRINT_OPERAND_SIZE-n_address_chars-1,  "" );
    fprintf( f, "\n" );

    offs_t curpc;
    for( int i=0; i<length; ) {

        curpc = address + i;

        switch( memory[curpc] ) {

            case MEMORYTYPE_UNKNOWN:
                {
                    offs_t pcbyte = space.address_to_byte(curpc) & space.addrmask();
                    uint8_t data = machine.debugger().cpu().read_opcode(space, pcbyte, 1 );

                    fprintf( f, "%-*s %-*s $%02x%*s ;",
                        DASM_PRINT_LABEL_SIZE,    get_label(curpc).c_str(),
                        DASM_PRINT_OPERATOR_SIZE, byte_declaration,
                        (int) data,
                        DASM_PRINT_OPERAND_SIZE-3,  "" );

                    fprintf( f, " [%0*x] %02x%-*s",
                        n_address_chars,            curpc,
                                                    data,
                        max_instruction_length*3-1, ""     );

                    fprintf( f, " %c%c%c%c%c%c%c%c",
                        ( data & 0x80 ) ? '#' : '.',
                        ( data & 0x40 ) ? '#' : '.',
                        ( data & 0x20 ) ? '#' : '.',
                        ( data & 0x10 ) ? '#' : '.',
                        ( data & 0x08 ) ? '#' : '.',
                        ( data & 0x04 ) ? '#' : '.',
                        ( data & 0x02 ) ? '#' : '.',
                        ( data & 0x01 ) ? '#' : '.' );

                    if( data >= ' ' && data <= '~' ) {
                        fprintf( f, " '%c'", (char) data );
                    }
                    else {
                        data &= 0x7F;
                        if( data >= ' ' && data <= '~' ) {
                            fprintf( f, " '%c' | 0x80", (char) data );
                        }
                    }
                    i++;
                }
                break;

            case MEMORYTYPE_INSTRUCTION:
                {
                    INSTRUCTION &instruction = instructions[curpc];

                    fprintf_instruction( f, instruction, false );

                    i += instruction.length;
                }
                break;

            default:
                fprintf( f, "%0*x: fatal - bad memory type 0x%02x.  exiting.", n_address_chars, curpc, memory[curpc] );
                exit(-1);
                break;
        }

        fprintf( f, "\n" );
    }

    fclose(f);
 
    return true;
}

static const std::string whitespace = " \t\n\r";
void tomc_instruction_hook(device_debug &debug, running_machine &machine, offs_t curpc, bool implicit )
{
    // this is horribily ineffiecient, but for now we do a strcmp to see if this is
    // the "maincpu".  if not, we return (ie. we don't disassemble anything bu the maincpu)
    if( strncmp( debug.m_device.m_tag.c_str(), ":maincpu", 8 ) ) {
        // not the main cpu - bail immediately
        return;
    }

    tuck_debug = &debug;

    if( firstTimeSetup ) {

        // this is not sufficient...
        if( strcasestr( debug.m_device.name(), "6809" ) ) {
              byte_declaration = (char const *) "FCB";
            equate_declaration = (char const *) "EQU";
        }
        else {
            byte_declaration = (char const *) "byte";
            equate_declaration = (char const *) "=";
        }

#ifdef TOMCXXX_FIXTHIS
        /* make sure that any required devices have been allocated */
        image_interface_iterator iter(machine.root_device());
        for (device_image_interface *image = iter.first(); image != NULL; image = iter.next())
        {
            /* is an image specified for this image */
            const char *image_name = machine.options().device_option(*image);

            if ((image_name != NULL) && (image_name[0] != '\0')) {
                printf( "TOMCXXX: SETUP image name is %s\n", image_name ); // TOMCXXX want to maybe automate default address range from image?
            }
        }
#endif /* TOMCXXX_FIXTHIS */

        firstTimeSetup = false;
    }

    if( curpc >= 0 && curpc < MEMORY_MAX ) {

        MEMORYTYPE mtype = memory[curpc];

        if( mtype == MEMORYTYPE_MIDINSTRUCTION ) {
            fprintf( stderr, "warning: executing mid-instruction %08x\n", curpc );
            if( labels.find(curpc) != labels.end() ) {
                mid_instruction_addresses.insert(curpc);
            }
            mtype = MEMORYTYPE_UNKNOWN;
        }

        switch( mtype ) {

            case MEMORYTYPE_UNKNOWN:
                {
                    // first time executing this location
                    debug_disasm_buffer buffer(debug.device());
                    std::string disassembled_string;
                    offs_t next_pc, size;
                    u32 dasmresult;
                    buffer.disassemble(curpc, disassembled_string, next_pc, size, dasmresult);

                    INSTRUCTION instruction;
                    instruction.address         = curpc;
                    instruction.execution_order = execution_counter++;
                    instruction.length          = dasmresult & util::disasm_interface::LENGTHMASK;
                    instruction.flags           = 0;
                    instruction.dasmresult      = dasmresult;
                    instruction.implicit        = implicit;
                    instruction.entry_caller    = BADADDRESS;


                    // fill operatr and operand
                    instruction.operatr = disassembled_string;
                    instruction.operand = "";

                    //skip leading whitespace
                    while( instruction.operatr.find_first_of( whitespace ) == 0 ) {
                        instruction.operatr = instruction.operatr.substr(1);
                    }

                    int i = instruction.operatr.find_first_of( whitespace );
                    if( i > 0 ) {
                        instruction.operand = instruction.operatr.substr(i);
                        instruction.operatr = instruction.operatr.substr(0,i);
                    }

                    //skip leading whitespace
                    while( instruction.operand.find_first_of( whitespace ) == 0 ) {
                        instruction.operand = instruction.operand.substr(1);
                    }

                    {
                        address_space &space = debug.m_memory->space(AS_PROGRAM);
                        offs_t pcbyte = space.address_to_byte(instruction.address) & space.addrmask();
                        static char tmpbuf[1024+1];
                        for( int i=0; i<instruction.length; i++ ) {
                            sprintf( tmpbuf, "%02x ", (int) machine.debugger().cpu().read_opcode(space, pcbyte + i, 1 ) );
                            instruction.hexbytes += tmpbuf;
                        }
                    }

                    for( int i=0; i<NINSTRUCTION_FLAGS; i++ ) {
                        if( !core_stricmp( instruction.operatr.c_str(), instruction_flags[i].operatr ) ) {
                            instruction.flags = instruction_flags[i].flags;
                            break;
                        }
                    }

                    instructions[curpc]     = instruction;

                    memory[curpc] = MEMORYTYPE_INSTRUCTION;
                    for( int i=1; i<instruction.length; i++ ) {
                        // just mark everything to make sure we never enter here later
                        memory[curpc+i] = MEMORYTYPE_MIDINSTRUCTION;
                    }

                    // mark implicit code...
                    if( instruction.flags & IF_NEWENTRYPOINT ) {
                        offs_t target_address = tomc_parse_target_address( instruction.operand );
                        if( target_address ) {
                            assign_label( ( instruction.flags & IF_SUBROUTINE ) ? LABEL_SUB : LABEL_JMP, target_address );
                            mark_implicit_code( target_address, instruction.address );
                        }
                        if( instruction.flags & IF_CONDITIONAL ) {
                            // for conditional branches, we want to also mark the "fallthrough" (next) instruction
                            // as well to make sure we mark both conditional possibilities (true and false).
                            //
                            // BUT... since the 6502 has no "BRA" instruction, it became common practice
                            // to do things like:
                            //      lda #0
                            //      beq  xxxx
                            // to simulate a "branch always".  in this case, the "next instruction" is truly
                            // unreachable (at least via fallthrough) and it would be a mistake to add it
                            // to our implicit list.  we could be trying to interpret data as code that way
                            // like most other disassemblers (precisely what we are trying to avoid with
                            // this "instrumented disassembly" effort).
                            //
                            // we probably can't catch 100% of these kinds of things easily, so we just try
                            // some simple checks here to at least make an effort (it catches the cases
                            // encountered so far)...
                            bool skip = false;
                            INSTRUCTION lastinstruction = instructions[lastpc];
                            if( lastinstruction.operatr.c_str() &&
                                lastinstruction.operand.c_str() &&
                                    instruction.operatr.c_str() &&
                                    instruction.operand.c_str() ) {
                                if( strlen( lastinstruction.operatr.c_str() ) > 2 &&
                                    strlen( lastinstruction.operand.c_str() ) > 2 &&
                                    strlen(     instruction.operatr.c_str() ) > 2 ) {
                                    if( ( lastinstruction.operatr.c_str()[0] == 'l' ||
                                          lastinstruction.operatr.c_str()[0] == 'L'    ) &&
                                        ( lastinstruction.operatr.c_str()[1] == 'd' ||
                                          lastinstruction.operatr.c_str()[1] == 'D'    ) &&
                                        ( lastinstruction.operand.c_str()[0] == '#' ||
                                          lastinstruction.operand.c_str()[0] == '#'    ) ) {
                                        int i = 1;
                                        bool iszero = true;
                                        if( lastinstruction.operand.c_str()[i] == '$' ) {
                                            i++;
                                        }
                                        while( lastinstruction.operand.c_str()[i] != '\0' ) {
                                            if( lastinstruction.operand.c_str()[i] != '0' ) {
                                                iszero = false;
                                            }
                                            i++;
                                        }
                                        if( ( instruction.operatr.c_str()[0] == 'b' ||
                                              instruction.operatr.c_str()[0] == 'B' ) ) {
                                            if( ( instruction.operatr.c_str()[1] == 'e' ||
                                                  instruction.operatr.c_str()[1] == 'E' ) &&
                                                ( instruction.operatr.c_str()[2] == 'q' ||
                                                  instruction.operatr.c_str()[2] == 'Q' ) ) {
                                                if( iszero ) {
                                                    skip = true;
                                                }
                                            }
                                            else if( ( instruction.operatr.c_str()[1] == 'n' ||
                                                       instruction.operatr.c_str()[1] == 'N' ) &&
                                                     ( instruction.operatr.c_str()[2] == 'e' ||
                                                       instruction.operatr.c_str()[2] == 'E' ) ) {
                                                if( !iszero ) {
                                                    skip = true;
                                                }
                                            }
                                        }
                                        fprintf(stderr, "TOMCXXX: %d lastinstruction [%04x] <%s> <%s>   this [%04x] <%s> <%s>\n",
                                                    skip ? 1 : 0,
                                                    lastinstruction.address,
                                                    lastinstruction.operatr.c_str(),
                                                    lastinstruction.operand.c_str(),
                                                    instruction.address,
                                                    instruction.operatr.c_str(),
                                                    instruction.operand.c_str() );
                                    }
                                }
                            }

                            if( !skip ) {
                                // ok - it made it through our tests... mark it implict...
                                mark_implicit_code( instruction.address + instruction.length, instruction.address );
                            }
                        }
                        else if( instruction.flags & IF_SUBROUTINE ) {
                            // just in case the subroutine never returns, mark next instruction as implicit
                            mark_implicit_code( instruction.address + instruction.length, instruction.address );
                        }
                    }
                }
                /* fallthrough! */

            case MEMORYTYPE_INSTRUCTION:
                {
                    // already been here before
                    assert( instructions.find(curpc) != instructions.end() );
                    INSTRUCTION &instruction     = instructions[curpc];
                    if( lastpc >= 0 ) {
                        // update implicit status
                        if( !implicit ) {
                            instruction.implicit = implicit;
                        }

                        // update caller_counts
                        if( instruction.caller_counts.find(lastpc) == instruction.caller_counts.end() ) {
                            instruction.caller_counts[lastpc] = 1;
                        }
                        else {
                            instruction.caller_counts[lastpc] += 1;
                        }
                    }
                }
                break;

            default:
                fprintf( stderr, "fatal: unknown memory type %02x\n", mtype );
                break;
        }
        lastpc = curpc;
    }
}
