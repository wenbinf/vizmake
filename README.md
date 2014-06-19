VizMake
=======

## Description

Vizmake visualizes `make`. It runs a modified GNU `make` to collect trace data
and visualizes some useful information of Makefile. Visualization provides
developers great insight of the make process.

Current implementation supports:

* Viewing what commands are actually invoked during build time.
* Visualizing lines in Makefile that reference variables and the actual value of
  a referenced variable during build time. [Mac OS X and Linux]
* Analyzing and visualizing dependencies in rules to help figure out what dependencies are potentially missed or are potentially extra. [Linux (rely on strace)]

## Installation and Usage

Let $(VIZMAKE) be the path of the root directory of vizmake project.

* Go into $(VIZMAKE)/make/ directory to build the modified version of GNU make. The binary
  file `make` should be in the $(VIZMAKE)/make directory.
* Run `python $(VIZMAKE)/vizmake.py` in any project as how you run `make`. Think of `python
  vizmake.py` as a `make` wrapper. You can pass any `make` command line
  arguments to `python $(VIZMAKE)/vizmake.py`. 
* There are some special command line arguments that vizmake.py will consume before they reach `make`:
  * --logdir, used for specifying where the log files are written to and read from, default is '/tmp'
  * --no-build, tell vizmake.py to start processing the logs in --logdir without invoking `make` first.
* Open web browser to see http://localhost:8000

## Screenshots

### Run vizmake
This screenshot is in a terminal after running

			python $(VIZMAKE)/vizmake.py all

which is equivalent to

			make all

except for doing visualization:
![screenshot](https://github.com/wenbinf/vizmake/raw/master/doc/vizmake_run.png)

### Index page

This screenshot is in a browser showing all `make` processes and all command
processes (e.g., gcc) spawned from a `make` process:
![screenshot](https://github.com/wenbinf/vizmake/raw/master/doc/vizmake_index.png)

### Full command line page

This screenshot is in a browser showing the full command line to execute a
process after clicking on one CMD link in the index page:
![screenshot](https://github.com/wenbinf/vizmake/raw/master/doc/vizmake_cmd.png)

### Makefile variable view page

This screenshot is in a browser showing the visualization of Makefile's variable
view after clicking on one VAR link in the index page:
![screenshot](https://github.com/wenbinf/vizmake/raw/master/doc/vizmake_var.png)

This page visualizes the lines in a Makefile that reference some variables.  It
also visualizes the information of each referenced variable during build time,
including the variable value, the source of variable definition, and other
variables referenced by a variable.

### Makefile dependency view page

This screenshot is in a browser showing the visualization of dependencies in rules
view after clicking on one DEP link in the index page:
![screenshot](https://github.com/wenbinf/vizmake/raw/master/doc/vizmake_dep.png)

## Demo

http://wenbinf.github.com/vizmake/demo

## License

GPLv3
