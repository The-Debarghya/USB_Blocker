# USB_Blocker

I was tinkering with the `proc` directory in Linux systems and thought we could leverage the mounts being registered there and prevent copying/moving of files(or type of files, for broader aspect) to the USB drives. Now why is that important? Ans - Automated USB drives are a physical cyber-threat to data-loss, which use automated scripts to steal data from the machine, this method is a way to prevent that.

- Here I've used `FANotify` to monitor the mounts from proc directory and prevented the transfer of pdf files if any FD's are found copying them to the monitored drive.
