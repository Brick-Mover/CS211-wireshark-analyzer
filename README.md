# CS211-wireshark-analyzer
UCLA F17 CS211 Team Project

When playing a game, remember the start and end No. of packets during active and idle periods, respectively.
For instance, user may be playing during packet No.100\~200, and do nothing during packet No.1200\~1600. 
First save the wireshark log as a .csv file, e.g. cocLog.csv.
Then use command:
```
./main.py cocLog.csv 100 200 1200 1600 <your phone's IP addr>
```
