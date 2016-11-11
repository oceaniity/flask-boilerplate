# Flask Boilerplate Dashboard

Bolts, batteries and nuts included. The goal of this repo is to provide a 
boilerplate project that I would love to use and is easy to set up when I need
to build different dashboard products.

## Some notes on design choices

Of which I have made several and you should probably read...

### Connectivity / databases

This application is built with the intention of being able to connect to a back-
end API or roll its own database. It's conceivable you might want to run 
different versions (at least I do) and that's why both functions are included.

In all cases where a database is required I have decided to stick with SQLite
(either on-disk or in-memory). It's just great and really I don't need federated 
solutions yet. 

The option is there, however.

### Vanilla milkshake

I have tried to use as many built in libraries as possible. After the trauma of 
NodeJS I think this is important.

