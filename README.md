# Pyranoid_Signal
A personal connection monitor, I think some screens and what not should explain it well, for windows users that get too high and want to know each and every process making a TCP or UPD connection with google search for the exe tied to PID to a whois lookup on the remote addrs (sorry Ipv4 only atm)

### Run the pyranoid_signal.py
When it loads, your prompted for type of connection to freak out about, pick one and let the magic happen!
<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/0d980db5-76b5-4d37-af23-fa1bc4ef9652" />

Because you haven't whitelisted your known safe processes and signed safe processes, at first it is a bit noisey.
<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/3cea5bc4-4ff2-4a6e-b52f-480c6229f8b8" />


### Run the whitelist_manager.py 
Use this stupid gui if you want you can double click on the orangey descriptions and it adds the process to the whitelist.txt, no reloads required soon youre monitor will be as quite as a church mouse, while still logging all active TCP or UDP connections while its running to a .cvs file. The few alerts that do show up are either trouble or processes that need to be whitelisted. The idea here is to know every process making a connection on your stupid windows computer :D

<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/dbbcc4ae-fcf5-4988-a393-bb86ae835a47" />

### Open pys_log_dashboard.html !
Click on the browse button and load the latest .csv log, the executable for making the connection is orange, if you hover over it, it pops up a tool tip that shows the full path, if youre suspicious, im bootylicious and you can click on the .exe and a google search about that process opens. Like wise the remote addr are linked to whois, so for the deep dive after smoking a bowl this is pretty slick.

<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/2c293ead-4a61-4afb-bc1d-7e6893ce73b2" />
