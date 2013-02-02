#! /usr/bin/env python3

import os

mamedir = "/z/build/linux64/emulators/mame"
os.chdir( mamedir )
with open( "mame64.gdb", "w" ) as f:
    print( "# source directories...", file=f )
    for root,dirs,files in os.walk( "src" ):
        for checkFile in files:
            if checkFile[-2:] == '.c':
                print( "directory {}".format( os.path.join( mamedir, root ) ), file=f )
                break
            
    print( """

# load the (HUGE) umed executable / symbol table
print "loading mame64... please wait (may take a while)"
file mame64

set args "-skip_gameinfo" "-rompath" "/z/emulation/resources/mame/roms;/z/emulation/resources/mame/chds;/z/emulation/resources/mame/software" "-samplepath" "/z/emulation/resources/mame/samples" "-artpath" "/z/emulation/resources/mame/artwork;/z/emulation/resources/mame/effects;/z/build/linux64/emulators/mame/artwork" "-cfg_directory" "/z/emulation/simple/mame_runtime/cfg" "-nvram_directory" "/z/emulation/simple/mame_runtime/nvram" "-input_directory" "/z/emulation/simple/mame_runtime/inp" "-state_directory" "/z/emulation/simple/mame_runtime/sta" "-snapshot_directory" "/z/emulation/simple/mame_runtime/snap" "-diff_directory" "/z/emulation/simple/mame_runtime/diff" "-comment_directory" "/z/emulation/simple/mame_runtime/comments" "-cheatpath" "/z/emulation/simple/mame_runtime/cheat/cheat_-d;/z/emulation/simple/mame_runtime/cheat/cheat" "-hashpath" "/z/build/linux64/emulators/mame/hash" "-cheat" "-video" "opengl" "-window" "-d" "a800" "starraid"


# set up predefined breakpoints
print ""
print "things you may want to do:"
print "    br mame_execute"
print "    br device_debug::instruction_hook"
print "    run"
print ""
print "have fun."
print ""
""", file=f )

print( "wrote mame64.gdb.  to run: ( cd {}; ddd -debugger \"gdb -silent -ex 'source mame64.gdb'\" )".format( mamedir ) )
