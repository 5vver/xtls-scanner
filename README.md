# XTLS Scanner

## Key features

- Provided SNI scanner (checks ping from host to SNI to determine the best one)
- Url scanner (test connection latency to Reality URL domain)
- TCP scanner (test connection latency to your Xray core server)
- Overall connection to address (IP, CIDR or domain)
- Maybe add geo countries IsoCodes

## Agents

- I/O supervisor scheduler agent: interacts with client and all the system agents.
- Event handler agent: handles all the events and errors (on event or error puts events to app shared state pool).
- SNI scanner agent: scans the SNI and checks the ping from host to SNI to determine the best one.
- URL/TCP scanner agent: scans the URL and TCP connection to your Xray core server.
- \*\* Reporter agent: basic logging, processes output data to user-friendly format.
