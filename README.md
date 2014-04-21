client-fuzzball
===============

*Currently client-fuzzball is in pre-alpha and should not be used.*

A fuzzing framework written in scapy.  The project is intended to accomplish the following, according to configurable definitions for "success", "failure", and "test":

- repeatedly fuzz-test a client or server using `scapy`'s fuzzing and packet manipulation abilities
- analyze a packet dump of a fuzzing session and produce a summary of test coverage, including attempted correlation of failed vs successful tests

Motivation
----------

client-fuzzball was motivated by some frustrating DHCP client debugging sessions.  
