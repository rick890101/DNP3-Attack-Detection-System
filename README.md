# DNP3 Attack Detection System for Scapy

The Distributed Network Protocol (DNP3) is defined in [IEEE Std 1815](https://standards.ieee.org/findstds/standard/1815-2012.html) for the purpose of distributing event data for operation on a variety of communication media consistent with the makeup of most electric power communication systems.

In this project we use the DNP3 libraries for Scapy to build a simple packet dissector that tries to detect anomalous DNP3 traffic by analysing its parameters. 

The program sniffs all traffic in eth0 interface and works in a similar way that an IDS, reporting suspicious events. Aditionally, there is a system that stores global alarm state and gives feedback to the user.

Please note that this code depends on the [scapy](http://www.secdev.org/projects/scapy/doc/index.html) library.

Usage:

```shell=
sudo ./sniff.py 
```

## License of DNP3_Lib

Copyright 2014-2016 N.R Rodofile

Licensed under the GPLv3.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.
