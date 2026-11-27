# CSC361 Assignment 3
## R1
### Running Instructions
In console, type 
```python
python3 traceroute_analysis.py PcapTracesAssignment3/<tracefile>
```
## R2
### Running Instructions
In console, type
```python
python3 r2.py
```
### Analysis
#### Answer to 2nd Question
- In Group 1, the sequence of router hops are not the same across the five trace files
- Occurs at hops 12 and 13.

At the 12th hop, the files trace1, trace3, and trace4 have the intermediate router `74.125.37.91` while trace files trace2 and trace5 have `72.14.237.123`.

At the 13th hop, all trace files have different intermediates routers.
- trace1: `209.85.250.121`
- trace2: `209.85.249.109`
- trace3: `209.85.245.65`
- trace4: `209.85.246.219`
- trace5: `209.85.250.59`

These hops are inside google's network, which use load balancing and hash the headers to pick a path. Linux traceroutes use different ports for each probe so the hash is different, which makes the path different.

For Group 2, the sequence of router hops are the same

#### Answer to 4th Question

Since only group 2 has the same sequence across the 5 files; group 1 will not be covered

From the table printed out by `r2.py`, we can see that hop to the router `24.108.0.1` has the highest average jump in latency across the different files.