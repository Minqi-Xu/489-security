For exploit1, the way to print out flag is simply fopen the file, then read character one by one and output it.

For exploit2 and exploit3, I have determined that the sys_write is banned by sandbox(so do writev, pwrite, etc, any syscall that can directly output to stdout or stderr are banned). Also, the system("cat /home/seed/flag") has no output. My first guess was the stdout or stderr was redirected. But trying redirect the output to file, I found that the file is not created. So I am guessing that maybe system will not accept any parameters.
