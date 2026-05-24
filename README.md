# Pyranoid_Signal
A personal connection monitor, I think some screens and what not should explain it well, for windows users that get too high and want to know each and every process making a TCP or UPD connection with google search for the exe tied to PID to a whois lookup on the remote addrs (sorry Ipv4 only atm)

### Run the pyranoid_signal.py
Because you haven't whitelisted your known safe processes and signed safe processes, at first it is a bit noisey.
<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/3cea5bc4-4ff2-4a6e-b52f-480c6229f8b8" />

When it loads, your prompted for type of connection to freak out about, *pick one and let the magic happen!*
<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/0d980db5-76b5-4d37-af23-fa1bc4ef9652" />



### Run the whitelist_manager.py 
```Use this stupid gui if you want you can double click on the orangey descriptions and it adds the process to the whitelist.txt, no reloads required soon your monitor will be as quite as a church mouse, while still logging all active TCP or UDP connections while its running to a .cvs file. The few alerts that do show up are either trouble or processes that need to be whitelisted. The idea here is to know every process making a connection on your stupid windows computer :D (-youre +your dont grammar hate)```

<img width="600" height="450" alt="image" src="https://github.com/user-attachments/assets/dbbcc4ae-fcf5-4988-a393-bb86ae835a47" />

### Open pys_log_dashboard.html !
Click on the browse button on the dashboard page and load logs from captures, the executable responsile for the connection is orange, if you hover over - it pops up a tool tip that shows the full path taken from the PID resolution, not from a db. if youre suspicious, im bootylicious (and I blow kisses) - you can click on the .exe and a google search about that process opens in your default browser. Like wise the remote_addr are links that can be used with the default who is, but you can give this tool some OSINT (edit the pys_log_dashboard.html and press [Control+F] search: "whosis.com" and replace the URL line with this:

``` `https://whatismyipaddress.com/ip/${encodeURIComponent(ip)}`; ```

<img width="800" height="600" alt="it can do so much more" src="https://github.com/user-attachments/assets/2c293ead-4a61-4afb-bc1d-7e6893ce73b2" />
