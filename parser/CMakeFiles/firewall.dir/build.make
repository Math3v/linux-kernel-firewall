# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/matej/dev/linux/pds/linux-kernel-firewall/parser

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/matej/dev/linux/pds/linux-kernel-firewall/parser

# Include any dependencies generated for this target.
include CMakeFiles/firewall.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/firewall.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/firewall.dir/flags.make

CMakeFiles/firewall.dir/snazzle.tab.c.o: CMakeFiles/firewall.dir/flags.make
CMakeFiles/firewall.dir/snazzle.tab.c.o: snazzle.tab.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/matej/dev/linux/pds/linux-kernel-firewall/parser/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object CMakeFiles/firewall.dir/snazzle.tab.c.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/firewall.dir/snazzle.tab.c.o -c /home/matej/dev/linux/pds/linux-kernel-firewall/parser/snazzle.tab.c

CMakeFiles/firewall.dir/snazzle.tab.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/firewall.dir/snazzle.tab.c.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/matej/dev/linux/pds/linux-kernel-firewall/parser/snazzle.tab.c > CMakeFiles/firewall.dir/snazzle.tab.c.i

CMakeFiles/firewall.dir/snazzle.tab.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/firewall.dir/snazzle.tab.c.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/matej/dev/linux/pds/linux-kernel-firewall/parser/snazzle.tab.c -o CMakeFiles/firewall.dir/snazzle.tab.c.s

CMakeFiles/firewall.dir/snazzle.tab.c.o.requires:
.PHONY : CMakeFiles/firewall.dir/snazzle.tab.c.o.requires

CMakeFiles/firewall.dir/snazzle.tab.c.o.provides: CMakeFiles/firewall.dir/snazzle.tab.c.o.requires
	$(MAKE) -f CMakeFiles/firewall.dir/build.make CMakeFiles/firewall.dir/snazzle.tab.c.o.provides.build
.PHONY : CMakeFiles/firewall.dir/snazzle.tab.c.o.provides

CMakeFiles/firewall.dir/snazzle.tab.c.o.provides.build: CMakeFiles/firewall.dir/snazzle.tab.c.o

CMakeFiles/firewall.dir/lex.yy.c.o: CMakeFiles/firewall.dir/flags.make
CMakeFiles/firewall.dir/lex.yy.c.o: lex.yy.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/matej/dev/linux/pds/linux-kernel-firewall/parser/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object CMakeFiles/firewall.dir/lex.yy.c.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/firewall.dir/lex.yy.c.o -c /home/matej/dev/linux/pds/linux-kernel-firewall/parser/lex.yy.c

CMakeFiles/firewall.dir/lex.yy.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/firewall.dir/lex.yy.c.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/matej/dev/linux/pds/linux-kernel-firewall/parser/lex.yy.c > CMakeFiles/firewall.dir/lex.yy.c.i

CMakeFiles/firewall.dir/lex.yy.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/firewall.dir/lex.yy.c.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/matej/dev/linux/pds/linux-kernel-firewall/parser/lex.yy.c -o CMakeFiles/firewall.dir/lex.yy.c.s

CMakeFiles/firewall.dir/lex.yy.c.o.requires:
.PHONY : CMakeFiles/firewall.dir/lex.yy.c.o.requires

CMakeFiles/firewall.dir/lex.yy.c.o.provides: CMakeFiles/firewall.dir/lex.yy.c.o.requires
	$(MAKE) -f CMakeFiles/firewall.dir/build.make CMakeFiles/firewall.dir/lex.yy.c.o.provides.build
.PHONY : CMakeFiles/firewall.dir/lex.yy.c.o.provides

CMakeFiles/firewall.dir/lex.yy.c.o.provides.build: CMakeFiles/firewall.dir/lex.yy.c.o

CMakeFiles/firewall.dir/test.c.o: CMakeFiles/firewall.dir/flags.make
CMakeFiles/firewall.dir/test.c.o: test.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/matej/dev/linux/pds/linux-kernel-firewall/parser/CMakeFiles $(CMAKE_PROGRESS_3)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object CMakeFiles/firewall.dir/test.c.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/firewall.dir/test.c.o -c /home/matej/dev/linux/pds/linux-kernel-firewall/parser/test.c

CMakeFiles/firewall.dir/test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/firewall.dir/test.c.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/matej/dev/linux/pds/linux-kernel-firewall/parser/test.c > CMakeFiles/firewall.dir/test.c.i

CMakeFiles/firewall.dir/test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/firewall.dir/test.c.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/matej/dev/linux/pds/linux-kernel-firewall/parser/test.c -o CMakeFiles/firewall.dir/test.c.s

CMakeFiles/firewall.dir/test.c.o.requires:
.PHONY : CMakeFiles/firewall.dir/test.c.o.requires

CMakeFiles/firewall.dir/test.c.o.provides: CMakeFiles/firewall.dir/test.c.o.requires
	$(MAKE) -f CMakeFiles/firewall.dir/build.make CMakeFiles/firewall.dir/test.c.o.provides.build
.PHONY : CMakeFiles/firewall.dir/test.c.o.provides

CMakeFiles/firewall.dir/test.c.o.provides.build: CMakeFiles/firewall.dir/test.c.o

# Object files for target firewall
firewall_OBJECTS = \
"CMakeFiles/firewall.dir/snazzle.tab.c.o" \
"CMakeFiles/firewall.dir/lex.yy.c.o" \
"CMakeFiles/firewall.dir/test.c.o"

# External object files for target firewall
firewall_EXTERNAL_OBJECTS =

firewall: CMakeFiles/firewall.dir/snazzle.tab.c.o
firewall: CMakeFiles/firewall.dir/lex.yy.c.o
firewall: CMakeFiles/firewall.dir/test.c.o
firewall: CMakeFiles/firewall.dir/build.make
firewall: CMakeFiles/firewall.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX executable firewall"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/firewall.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/firewall.dir/build: firewall
.PHONY : CMakeFiles/firewall.dir/build

CMakeFiles/firewall.dir/requires: CMakeFiles/firewall.dir/snazzle.tab.c.o.requires
CMakeFiles/firewall.dir/requires: CMakeFiles/firewall.dir/lex.yy.c.o.requires
CMakeFiles/firewall.dir/requires: CMakeFiles/firewall.dir/test.c.o.requires
.PHONY : CMakeFiles/firewall.dir/requires

CMakeFiles/firewall.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/firewall.dir/cmake_clean.cmake
.PHONY : CMakeFiles/firewall.dir/clean

CMakeFiles/firewall.dir/depend:
	cd /home/matej/dev/linux/pds/linux-kernel-firewall/parser && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/matej/dev/linux/pds/linux-kernel-firewall/parser /home/matej/dev/linux/pds/linux-kernel-firewall/parser /home/matej/dev/linux/pds/linux-kernel-firewall/parser /home/matej/dev/linux/pds/linux-kernel-firewall/parser /home/matej/dev/linux/pds/linux-kernel-firewall/parser/CMakeFiles/firewall.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/firewall.dir/depend

