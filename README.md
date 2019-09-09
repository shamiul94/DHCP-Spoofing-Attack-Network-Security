# DHCP-Spoofing-Attack-Network-Security

In this project, I am implementing DHCP Spoofing Attack. 
Details about this project is in the `Report.pdf` file. You can learn details about my implementation of the attack there. 

# Note - 
1. All the dhcp-spoofing codes are in `final-code` folder.  

2. In this project, I am implementing DHCP Spoofing Attack on Linux. I have run this attack on Ubuntu 18.04.2 LTS. It should work fine on later and recent Ubuntu versions too. To use it on Windows machine, you might have to change the code a bit. 

3. This project is completely based on `python3`. Some of the function doesn't work for `python2`. If you are using python2, you have to tweak the code in some places. 

4. I used `Pycharm` for coding. It's literally a magic. 

5. Modern OS has a pretty good counter measure against DHCP Spoofing. It skips discover and offer steps and sends request to the trusted dhcp server (router in most of the cases) and don't receive ack from any other dhcp server (evil or good) if and only if it was connected to this network in near past. You can beat this countermeasure by `DHCP starvation attack`. I tried to implement it too but due to lack of time, I couldn't complete it. If you can complete it, you can mail me at `shamiulhasan93@gmail.com` and I will edit it there. Or create an issue here. 

6. I have changed the gateway and IP address of the victim device. I haven't yet implemented the routing system. So, victim device can't access internet after an attack. In that sense it's not an MITM attack. Couldn't solve this problem. If you find a solution, let me know.

7. Other folders except `final-codes` contain codes which I read and tried to make things work. I think they might be useful for you to learn more about the attack.  

# Commands to run this code - 

1. Run the spoofer - 

```shell
sudo python3 dhcp_spoofer.py -i wlo1
```

2. Run the counter measure first- 
```shell
sudo python3 Counter_measure.py
```

Then run this command - 
```shell
sudo python3 send_discover.py
```

3. To run starvation (which doesn't work properly now. It sends dhcp requests infinitely but router doesn't send ACK packets in reply. will look into it later.) - 
```shell 
sudo python3 Request_starve.py
```