#!/usr/bin/env python
#                                                                                                           
# vizmake is a simple textual monitoring tool                                                               
#                                                                                                           
# Copyright (C) Wenbin Fang 2012 <wenbin@cs.wisc.edu>                                                      
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__appname__ = 'vizmake'
__version__ = "2.0.0"
__author__ = "Wenbin Fang <wenbin@cs.wisc.edu>"
__licence__ = "GPL"

# Data structure
#===============

class Var:
    """
    Description:
      It represents a variable.
    """
    def __init__(self):
        # all variable references
        self.var_refs = []

        # variable name
        self.name = ''

        # variable value (with other variable names)
        self.value = ''

        # variable value (after expansion)
        self.expanded_value = ''

        # variable type, should be one of those:
        # DEFAULT, COMMAND, FILE, UNDEFINED, AUTOMATIC, ENV
        self.type = ''

        # Location of variable definition, valid only when type = FILE
        self.filenm = ''
        self.lineno = ''

    def __str__(self):
        string = "VAR name=%s, value=%s, type=%s" % (self.name, self.value, self.type)
        if self.type == 'FILE':
            string = '%s, file=%s:%s' % (string, self.filenm, self.lineno)
        string = '%s\n-include: ' % string
        for var in self.var_refs:
            string = '%s%s ' % (string, var.name)
        string += '\n'
        return string
        
class Line:
    """
    Description:
      It represents a line in a makefile
    """
    def __init__(self, lineno, content):
        # all variable references
        self.var_refs = []

        # line content
        self.content = content

        # line number
        self.lineno = lineno

    def __str__(self):
        string = '%s -- %s\n' % (self.lineno, self.content)
        string += '- var_refs:\n'
        for var in self.var_refs:
            string = '%s%s\n' % (string, var)
        return string

class Command:
    """
    Description:
      It represents a line in a makefile
    """
    def __init__(self, filemn, lineno, content):
        # all variable references
        self.var_refs = []

        # line content
        self.content = content

        # Makefile path
        self.filemn = filemn

        # line number
        self.lineno = lineno

    def __str__(self):
        string = '%s:%s -- %s\n' % (self.filemn, self.lineno, self.content)
        string += '- var_refs:\n'
        for var in self.var_refs:
            string = '%s%s\n' % (string, var)
        return string

class MakeFile:
    """
    Description:
      It represents a makefile.
    """
    def __init__(self, filenm):
        # included makefiles
        self.inc_files = []

        # all lines
        self.lines = []

        # file name
        self.filenm = filenm

    def __str__(self):
        string = "== %s ==\n" % self.filenm
        string = "%s%s\n" % (string, "- includes:")
        for makefile in self.inc_files:
            string = "%s\t%s\n" % (string, makefile.filenm)

        string = "%s%s\n" % (string, "- lines:")
        for line in self.lines:
            string = "%s\t%s\n" % (string, line)

        for makefile in self.inc_files:
            string = "%s%s\n" % (string, makefile)
        return string

class Rule:
    """
    Description:
      Represent a rule
    """
    def __init__(self, target):
        self.target = target
        self.trg_filenm = ''
        self.trg_lineno = ''
        self.dependees = []
        self.cmd = []
        self.cmd_filenm = []
        self.cmd_lineno = []

        self.extra_dependees = []
        self.missing_dependees = []

    def update(self):
        pass

    def __str__(self):
        string = '* RULE\n'
        string = '%s-- Target: %s\n' % (string, self.target)
        for i in range(len(self.cmd)):
            string = '%s-- Cmd: %s\n' % (string, self.cmd[i])
        return string

class Process:
    """
    Description:
      Represent a process that runs a command
    """
    def __init__(self, pid, filenm, timestamp):
        # This process id
        self.pid = pid

        # Parent process id
        self.ppid = ''

        # Child processes
        self.children = []

        # Timestamp (the earliest one)
        self.timestamp = timestamp

        # The command to start cmd process
        self.exe = ''

        # The command to start make process
        self.make_exe = ''

        # Legal value: MAKE and CMD
        self.type = 'MAKE'

        # The trace data file names
        self.filenm = []
        self.filenm.append(filenm)

        # Detailed view url
        self.var_url = ''
        self.cmd_url = ''
        self.dep_url = ''

        #
        # Things to be used in visualization
        # These are only set when it is a make process
        #

        # The root makefile
        self.root_makefile = None
        
        # Variable reference
        self.var_refs = []

        # Command lines
        # Should be added to the correct line in makefile later
        self.cmds = []

        # Filename -> Line number -> Line
        self.file_line_map = dict()

        # target name -> Rule list
        self.rules = dict()

    def update(self):
        """
        Update attribute values in this structure
        """
        # Set attributes
        for filenm in self.filenm:
            with open(filenm) as f:
                cmd_exe = False
                for line in f:
                    line = line.rstrip()
                    elems = line.split('---')
                    if elems[0] == 'PARENT':
                        cmd_exe = False
                        self.ppid = elems[1]
                    elif elems[0] == 'EXE':
                        cmd_exe = False
                        self.exe = elems[2]
                    elif elems[0] == 'MAKE_EXE':
                        cmd_exe = False
                        self.make_exe = elems[1]
                    elif elems[0] == 'DEP':
                        cmd_exe = False
                        if elems[1] not in self.rules:
                            self.rules[elems[1]] = Rule(elems[1])
                        self.rules[elems[1]].dependees = elems[2].split(' ')
                    elif elems[0] == 'TARGET':
                        cmd_exe = False
                        if elems[1] not in self.rules:
                            self.rules[elems[1]] = Rule(elems[1])
                        self.rules[elems[1]].trg_filenm = elems[2]
                        self.rules[elems[1]].trg_lineno = elems[3]
                    elif elems[0] == 'CMD-EXE':
                        if elems[1] not in self.rules:
                            self.rules[elems[1]] = Rule(elems[1])
                        self.rules[elems[1]].cmd_filenm.append(elems[2])
                        self.rules[elems[1]].cmd_lineno.append(elems[3])
                        self.rules[elems[1]].cmd.append(elems[4])
                        self.last_rule = self.rules[elems[1]]
                        cmd_exe = True
                    elif len(elems) == 1:
                        if cmd_exe == False:
                            self.exe = "%s\n%s" % (self.exe, elems[0])
                        else:
                            self.last_rule.cmd[-1] += elems[0]
                    else:
                        cmd_exe = False
                        self.exe = ''
                        break

#        for trg, rule in self.rules.iteritems():
#            print rule
        # We only parse MAKE process
        if len(self.exe) > 0: 
            self.type = 'CMD'
            self.cmd_url = "make/cmd/%s" % self.pid
            return
        else:
            self.var_url = "make/var/%s" % self.pid
            self.cmd_url = "make/cmd/%s" % self.pid

        for filenm in self.filenm:
            self._parse(filenm)
            
        # Fix up command to lines
        self._fixup_commands()

    def _fixup_commands(self):
        """
        Fixup the variable reference for lines of commands
        
        Make program first evaluates variable references for target and 
        dependencies line by line. We build up all Line structure by this
        point.

        After it finishes one pass of parsing Makefile, it resolves 
        dependencies and evaluates variable references for commands.
        We need to catch up and fix those variable references to Line
        structure.
        """
        for cmd in self.cmds:
            line = self.file_line_map[cmd.filemn][cmd.lineno]
            line.var_refs = cmd.var_refs

    def _parse(self, filenm):
        """
        Parse Makefile and build up data structures
        """
        print "== Parsing %s" % filenm
        # The final several variables should not belong to command
        end_cmd_parsing = False
        with open(filenm) as f:
            makefiles = []
            vars_stack = []
            for line in f:
                line = line.rstrip()
#                print line
                elems = line.split('---')
                if elems[0] == 'START EVAL MAKEFILE':
                    makefiles.append(MakeFile(elems[1]))
                elif elems[0] == 'END EVAL MAKEFILE':
                    self.root_makefile = makefiles.pop()
                    if len(makefiles) > 0:
                        makefiles[-1].inc_files.append(self.root_makefile)
                elif elems[0] == 'EVAL LINE':
                    makefiles[-1].lines.append(Line(elems[1], elems[2]))
                    try:
                        self.file_line_map[makefiles[-1].filenm]
                    except:
                        self.file_line_map[makefiles[-1].filenm] = dict()
                    self.file_line_map[makefiles[-1].filenm][elems[1]] = makefiles[-1].lines[-1]

                elif elems[0] == 'VAR REF BEGIN':
                    vars_stack.append(Var())
                    if elems[1] == 'SHELL': end_cmd_parsing = True
                elif elems[0] == 'VAR REF END':
                    # FIXME
                    if elems[1] == 'AUTO':
                        continue
                    cur_var = vars_stack.pop()
                    cur_var.type = elems[1]
                    if cur_var.type == 'FILE':
                        cur_var.filenm = elems[4]
                        cur_var.lineno = elems[5]
                    cur_var.name = elems[2]
                    if cur_var.type != 'UNDEFINED':
                        cur_var.value = elems[3]
                        if cur_var.type == 'FILE':
                            cur_var.expanded_value = elems[6]
                        else:
                            cur_var.expanded_value = elems[4]
                    else:
                        cur_var.value = ''
                    if len(vars_stack) == 0:
                        try:
                            makefiles[-1].lines[-1].var_refs.append(cur_var)
                        except:
                            if end_cmd_parsing == False:
                                try:
                                    self.cmds[-1].var_refs.append(cur_var)
                                except:
                                    self.var_refs.append(cur_var)
                            else:
                                self.var_refs.append(cur_var)
                    else:
                        vars_stack[-1].var_refs.append(cur_var)
                elif elems[0] == 'CMD':
                    self.cmds.append(Command(elems[1], elems[2], elems[3]))
                elif len(elems) == 1:
                    try:
                        makefiles[-1].lines[-1].content += ("%s" % elems[0])
                    except:
                        try:
                            self.cmds[-1].content += elems[0]
                        except:
                            print elems[0]

    def __cmp__(self, other):
        if self.timestamp < other.timestamp: return -1
        elif self.timestamp == other.timestamp: return 0
        return 1

    def __str__(self):
        string = 'Process %s: %s\n' % (self.pid, self.type)
        string = "%s- ppid = %s\n" % (string, self.ppid)
        string = "%s- timestamp = %s\n" % (string, self.timestamp)
        string = "%s- files = [" % string
        for filenm in self.filenm:
            string = "%s %s " % (string, filenm)
        string = "%s]\n" % string
        string = "%s- var_url = %s\n" % (string, self.var_url)
        string = "%s- cmd_url = %s\n" % (string, self.cmd_url)
        string = "%s- exe = %s\n" % (string, self.exe)
        string = "%s- make_exe = %s\n" % (string, self.make_exe)
        string = "%s- children = [" % string
        for child in self.children:
            string = "%s %s " % (string, child.pid)
        string = "%s]\n" % string
        string = "%s- cmds:\n" % string
        for cmd in self.cmds:
            string = "%s- %s\n" % (string, cmd)
        string = "%s]\n" % string
        string = "%s- proc var refs:\n" % string
        for var in self.var_refs:
            string = "%s- %s\n" % (string, var)
        string = "%s]\n" % string
        return string
#
# Libraries
#==========

import re
import json
import sys
import os
import errno
import glob
import signal
import SimpleHTTPServer
import SocketServer
import time

#
# The core class of vizmake
#==========================

class VizMake:
    """
    Description:
      The central manager to visualize make
    """
    def __init__(self):
        # pid => Process
        self.proc_map = dict()

        # A list of make processes, sorted by timestamp
        self.make_procs = []

        self.virtual_working_dir = sys.argv[0][:-10]
        if len(self.virtual_working_dir) == 0:
            self.virtual_working_dir = './'

    def run(self):
        """
        Description:
        1. Run modified GNU make, which generates trace data in /tmp/vizmake_log*
        2. Process all /tmp/vizmake_log*, and build up data structures
        3. Generate index page
        4. Generate visualization pages
        5. Start web server
        """
        if self._make() == 0:
            self._process()
            self._gen_index()
            self._gen_vis()
            self._start_httpd()
        else:
            print "** Make fails ..."

    def _process(self):
        """
        Process /tmp/vizmake_log-pid-time files
        1. Iterate through all /tmp/vizmake_log* files
           1.1 Get pid from file name
           1.2 Construct process or add filenm to Process.filenm
        2. Iterate through all Process in self.proc_map
           2.1 Update it's fields
           2.2 Find its non-make child processes
        """
        for logfile in sorted(glob.glob('/tmp/vizmake_log*')):
            elems = logfile.split('-')
            pid = elems[1]
            timestamp = elems[2]
            if pid not in self.proc_map:
                self.proc_map[pid] = Process(pid, logfile, timestamp)
            else:
                self.proc_map[pid].filenm.append(logfile)
        
        for (pid, proc) in self.proc_map.iteritems():
            proc.update()
            if proc.type == 'CMD':
                try:
                    pproc = self.proc_map[proc.ppid]
                    pproc.children.append(proc)
                except:
                    print "cannot find", proc.ppid
            else:
                self.make_procs.append(proc)

        for (pid, proc) in self.proc_map.iteritems():
            proc.children = sorted(proc.children)

        self.make_procs = sorted(self.make_procs)

#        for proc in self.make_procs:
#            print proc

    def _gen_proc_list(self, proc):
        string = '<li>'
        proc_str = 'PID=%s' % proc.pid
        if proc.type == 'CMD':
            exe_str = proc.exe[:50]
            if len(proc.exe) > 50: exe_str += '...'
            proc_str = '<i>COMMAND %s: %s</i>' % (proc_str, exe_str)
            proc_str = '%s (<a href="%s.html" target="_blank">CMD</a>)' % (proc_str, proc.cmd_url)
        else:
            proc_str = 'MAKE %s: %s' % (proc_str, proc.root_makefile.filenm)
            proc_str = '%s (<a href="%s.html" target="_blank">CMD</a> | '\
                '<a href="%s.html" target="_blank">VAR</a>)' % \
                (proc_str, proc.cmd_url, proc.var_url)

        string += proc_str
        if len(proc.children) > 0:
            string += '<ul>'
            for child in proc.children:
                # We don't want to list subprocess with MAKE type to avoid
                # redundency
                if child.type == 'MAKE': continue
                string += self._gen_proc_list(child)
            string += '</ul>'
        string += '</li>'
        return string

    def _gen_index(self):
        """
        Generate an index page to display processes
        """
        with open('%svizengine/index.html' % self.virtual_working_dir, \
                      'w') as f:
            string = '<html><head><title>Analyze Makefile</title></head><body><ul>'
            for proc in self.make_procs:
#                print proc
                string += self._gen_proc_list(proc)
            string += '</ul></body></html>'
            f.write(string)

    def _gen_vis(self):
        """
        Generate visualization pages
        0. Create make directory if necessary
        1. Clean up all files in make directory
        2. Generate pages
        """
        os.system('mkdir -p %s/vizengine/make' % self.virtual_working_dir)
        os.system('rm -rf %s/vizengine/make/*' % self.virtual_working_dir)
        os.system('mkdir -p %s/vizengine/make/cmd' % self.virtual_working_dir)
        os.system('mkdir -p %s/vizengine/make/var' % self.virtual_working_dir)
        for pid, proc in self.proc_map.iteritems():
            self._visualize(proc)

    def _make(self):
        """
        A GNU make wrapper
        """
        make_cmd = "%smake/make" % self.virtual_working_dir
        for i in range(1, len(sys.argv)):
            make_cmd = "%s %s" % (make_cmd, sys.argv[i])
        print "== Running ", make_cmd
        os.system('rm -rf /tmp/vizmake_log*')
        return os.system(make_cmd)

    def _vis_var(self, var):
        """
        Visualize a variable
        """
        tooltip = "NO"
        string = '{'
        value = var.value[:80]
        if var.value != var.expanded_value:
            tooltip = "YES"
        if len(var.value) > 80: 
            value += '...'
            tooltip = "YES"
        tooltip = json.dumps(tooltip)
        name = '$(%s)="%s" ' % (var.name, value)
        if var.type == 'FILE':
            name += ('from %s:%s' % (var.filenm, var.lineno))
        elif var.type == 'COMMAND':
            name += 'from command line'
        elif var.type == 'UNDEFINED':
            name += 'that is undefined'
        elif var.type == 'AUTOMATIC':
            name += 'that is an automatic variable'
        elif var.type == 'DEFAULT':
            name += 'that is an default variable'
        elif var.type == 'ENV':
            name += 'from environment variable'
        name = json.dumps(name)
        string = '%s"name":%s,"full":%s,"type":"VAR","tooltip":%s,"children":[' % \
                 (string, name, json.dumps(var.expanded_value), tooltip)
        for var in var.var_refs:
            string += self._vis_var(var)
        string = string.rstrip(',')
        string += ']},'
        return string

    def _vis_line(self, line):
        """
        Visualize a line in a makefile
        """
        string = '{'
        content = line.content[:100]
        tooltip = "NO"
        if len(line.content) > 100: 
            content += '...'
            tooltip = "YES"
        tooltip = json.dumps(tooltip)
        name = "Line %s: %s" % (line.lineno, content)
        # TODO(wenbin): shorten name to within 50 characters
        name = json.dumps(name)
        string = '%s"name":%s,"full":%s,"type":"LINE","tooltip":%s,"children":[' % \
                 (string, name, json.dumps(line.content), tooltip)

        for var in line.var_refs:
            string += self._vis_var(var)
        string = string.rstrip(',')
        string += ']},'
        return string

    def _vis_file(self, makefile):
        """
        Visualize a makefile
        """
        string = '{'
        string = '%s"name":"%s","full":"","type":"FILE","children":[' % \
                 (string, makefile.filenm)
        string += '{'
        string = '%s"name":"INCLUDE FILES: %d in total","tooltip":"NO","type":"INC","children":[' % \
            (string, len(makefile.inc_files))
        for inc_file in makefile.inc_files:
            string += self._vis_file(inc_file)
        string = string.rstrip(',')
        string += ']},'
        string += '{'
        string = '%s"name":"LINES referencing variables: %d in total", "type":"LINES","children":[' % \
            (string, len([x for x in makefile.lines if len(x.var_refs) != 0]))
        for line in makefile.lines:
            if len(line.var_refs) == 0: continue
            string += self._vis_line(line)
        string = string.rstrip(',')
        string += ']}'
        string += ']},'
        return string

    def _visualize(self, proc):
        """
        Produce web pages a specified process `proc`

        In fact there are two types of pages
        1. Page about command, which is in essense the full text of command executed
        2. Page about makefile variables, which has such json format
          JSON format:
          {
          "name": "xxx",    // The text to display on each bar
          "type": "xxx",    // The type of each bar (FILE, LINE, VAR, INCS, LINES)
          "full": "xxx",    // Full content for LINE or VAR
          "tooltip": "XXX", // Need tool tip? possible values: YES / NO
          "children":[]     // Children
          }
        """
        base_path = '%svizengine' % self.virtual_working_dir

        # Handle CMD page
        with open('%s/%s.html' % (base_path, proc.cmd_url), 'w') as f:
            if proc.type == 'MAKE':
                f.write(proc.make_exe)
            else:
                f.write(proc.exe)
                return

        # Handle VAR page
        print "== Visualizing %s" % proc.root_makefile.filenm
        with open("%s/%s.json" % \
                      (base_path, proc.var_url), "w") as f:
            string = self._vis_file(proc.root_makefile)
            string = string.rstrip(',')
            f.write(string)
        cmd = 'cp %s/indented_tree/index.html %s/%s.html' % \
                      (base_path, base_path, proc.var_url)
        os.system(cmd)
        string = ''
        with open('%s/%s.html' % (base_path, proc.var_url), 'r') as f:
            string = f.read()
            string = string.replace('$$PID_VALUE$$', proc.pid)
        with open('%s/%s.html' % (base_path, proc.var_url), 'w') as f:
            f.write(string)

    def _start_httpd(self):
        """
        Set up a simple web server for visualization
        """
        os.chdir("%svizengine" % self.virtual_working_dir)
        httpd = None
        print "Starting web server for visualization ..."
        while True:
            try:
                Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
                httpd = SocketServer.TCPServer(("", 8000), Handler)
                print "Please visit this URL in your web browser:"
                print "    http://localhost:8000"
                print "    (Press ctrl+c to exit)"
                httpd.serve_forever()
            except KeyboardInterrupt:
                httpd.shutdown()
                print "Exit visualization"
                break
            except:
                print "Failed to listen to port 8000, wait 5 seconds ..."
                try:
                    time.sleep(5)
                except KeyboardInterrupt:
                    print "Failed to listen to port 8000. Please check whether this port is being used."
                    break
                continue
#
# Main
#======
def main():
    viz = VizMake()
    viz.run()

if __name__ == '__main__':
    main()

# The end
