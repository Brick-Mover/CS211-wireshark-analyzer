# CS211-wireshark-analyzer
UCLA F17 CS211 Team Project

When playing a game, remember the start and end No. of packets during active and idle periods, respectively.
For instance, user may be playing during packet No.100\~200, and do nothing during packet No.1200\~1600. 
First save the wireshark log as a .csv file, e.g. cocLog.csv. Then create a file, e.g. index.txt. In each row,
include three things: start index, end index, and a short description(no space), e.g.

100 200 playing
1200 1600 idle

Then use command:
```
./main.py cocLog.csv index.txt <your phone's IP addr>
```
