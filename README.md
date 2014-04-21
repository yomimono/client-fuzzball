client-fuzzball
===============

Currently client-fuzzball is in pre-alpha and should not be used.

A fuzzing framework written in scapy.  The project is intended to accomplish the following:

1) given parameters defining success, failure, and test construction, repeatedly fuzz-test a client or server using `scapy`'s fuzzing and packet manipulation abilities
2) analyze a packet dump of a fuzzing session according to parameters for success, failure, and test construction, and produce a summary of test coverage, including attempted correlation of failed vs successful tests

