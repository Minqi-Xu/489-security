Part 1 for Assignment 3


Question 1:
Function A: A(v) = v is a function that output its input.
Function B: B(s') takes a key and unix time as input, and output signature generated based on unix time with s' as key
Function C: C(A(v),B(s')) is a function verify the signature with v (which is a public key). It takes v and signature as input, and output a boolean value, true if the signature is generated in the past few seconds, otherwise false.


Question 2:
It does not prevent MITM attacks. Some effort is done to prevent MITM, for example, using private key and public key separately so that hacker cannot obtain the private key. Also, time is introduced to avoid MITM to login out of reasonable time window. But not enough to prevent MITM, because hacker can send B(s') directly to the server at the same time or even quicker than the user without known of the private key. That is if hacker can get the (u, B(s')), then quickly send it to the server, and then hacker will get the access.