		IDA processor/loader for EsetCrackme 2015

Well, finally after 1 year of having this on my hdd, there is public writeup for
crackme so here are my proc/loader IDA modules for EsetCrackme2015... After almost
1 year I thought that they will never see the light of day... Original plan was to
release them when ESET makes new crackme, or this one becomes obsolete. With public
writeup, I would say it's obsolete...

Package containes:
eset.py                 - copy to IDA\procs
esetloader.py           - copy to IDA\loaders
inject_process.bin      - vm code which performs injection into child process
rc4_vm_dump.bin         - vm code responsible for rc4 from kernel

							deroko of ARTeam
