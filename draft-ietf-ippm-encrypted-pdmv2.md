---
title: "IPv6 Performance and Diagnostic Metrics Version 2 (PDMv2) Destination Option"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-ietf-ippm-encrypted-pdmv2-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Transport"
workgroup: "IP Performance Measurement"
keyword:
 - Extension Headers
 - IPv6
 - PDMv2
 - Performance
 - Diagnostic
venue:
  group: "IP Performance Measurement"
  type: "Working Group"
  mail: "ippm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ippm/"
  github: "ameyand/PDMv2"
  latest: "https://ameyand.github.io/PDMv2/draft-elkins-ippm-encrypted-pdmv2.html"

author:
 -
    fullname: Nalini Elkins
    organization: Inside Products, Inc.
    email: "nalini.elkins@insidethestack.com"

 -
    fullname: Michael Ackermann
    organization: BCBS Michigan
    email: "mackermann@bcbsm.com"

 -
    fullname: Ameya Deshpande
    organization: NITK Surathkal/Google
    email: "ameyanrd@gmail.com"

 -
    fullname: Tommaso Pecorella
    organization: University of Florence
    email: "tommaso.pecorella@unifi.it"

 -
    fullname: Adnan Rashid
    organization: Politecnico di Bari
    email: "adnan.rashid@poliba.it"

normative:

informative:


--- abstract

RFC8250 describes an optional Destination Option (DO) header embedded
in each packet to provide sequence numbers and timing information as
a basis for measurements.  As this data is sent in clear- text, this
may create an opportunity for malicious actors to get information for
subsequent attacks.  This document defines PDMv2 which has a
lightweight handshake (registration procedure) and encryption to
secure this data.  Additional performance metrics which may be of use
are also defined.

--- middle

# Introduction

## Current Performance and Diagnostic Metrics (PDM)

The current PDM is an IPv6 Destination Options header which provides
information based on the metrics like Round-trip delay and Server
delay.  This information helps to measure the Quality of Service
(QoS) and to assist in diagnostics.  However, there are potential
risks involved transmitting PDM data during a diagnostics session.

PDM metrics can help an attacker understand about the type of machine
and its processing capabilities.  Inferring from the PDM data, the
attack can launch a timing attack.  For example, if a cryptographic
protocol is used, a timing attack may be launched against the keying
material to obtain the secret.

Along with this, PDM does not provide integrity.  It is possible for
a Man-In-The-Middle (MITM) node to modify PDM headers leading to
incorrect conclusions.  For example, during the debugging process
using PDM header, it can mislead the person showing there are no
unusual server delays.


## PDMv2 Introduction

PDMv2 adds confidentiality, integrity and authentication to PDM.

PDMv2 consists of three kinds of flows:

- Primary to Primary

- Primary to Secondary

- Secondary to Secondary

These terms are defined in Section 3.  Sample topologies may be found
in Appendix 1.

This document describes the Secondary to Secondary protocol and
security requirements.  The Primary to Primary and Primary to
Secondary protocol will be described in a subsequent document.


# Conventions used in this document

{::boilerplate bcp14-tagged}

# Terminology

-  Primary Client (PC): An authoritative node that creates
   cryptographic keys for multiple Secondary clients.

-  Primary Server (PS): An authoritative node that creates
   cryptographic keys for multiple Secondary servers.

-  Secondary Client (SC): An endpoint node which initiates a session
   with a listening port and sends PDM data.  Connects to the Primary
   Client to get cryptographic key material.

-  Secondary Server (SS): An endpoint node which has a listening port
   and sends PDM data.  Connects to the Primary Server to get
   cryptographic key material.

Note: a client may act as a server (have listening ports).

-  Symmetric Key (K): A uniformly random bitstring as an input to the
   encryption algorithm, known only to Secondary Clients and
   Secondary Servers, to establish a secure communication.

-  Public and Private Keys: A pair of keys that is used in asymmetric
   cryptography.  If one is used for encryption, the other is used
   for decryption.  Private Keys are kept hidden by the source of the
   key pair generator, but Public Key is known to everyone.  pkX
   (Public Key) and skX (Private Key).  Where X can be, any client or
   any server.

-  Pre-shared Key (PSK): A symmetric key.  Uniformly random
   bitstring, shared between any client or any server or a key shared
   between an entity that forms client-server relationship.  This
   could happen through an out-of band mechanism: e.g., a physical
   meeting or use of another protocol.

-  Session Key: A temporary key which acts as a symmetric key for the
   whole session.

# Protocol Flow

The protocol will proceed in 3 steps.

{:req: counter="bar" style="format R(%d)"}

{: req}
- Negotiation between Primary Server and Primary Client.
- Registration between Primary Server / Client and Secondary
  Server / Client
- PDM data flow between Secondary Client and Secondary Server

After-the-fact (or real-time) data analysis of PDM flow may occur by
network diagnosticians or network devices.  The definition of how
this is done is out of scope for this document.

## Registration Phase

### Rationale of Primary and Secondary Roles

Enterprises have many servers and many clients.  These clients and
servers may be in multiple locations.  It may be less overhead to
have a secure location (ex.  Shared database) for servers and clients
to share keys.  Otherwise, each client needs to keep track of the
keys for each server.

Please view Appendix 1 for some sample topologies and further
explanation.

### Diagram of Registration Flow

       +-----------+                      +-----------+
       |Primary    |<====================>|Primary    |
       |Client (PC)|                      |Server (PS)|
       +-----+-----+                      +-----+-----+
            ||                                  ||
            ||                                  ||
+-------------------------+         +-------------------------+
| Secondary Clients(SC's) |         | Secondary Servers (SS's)|
|                         |         |                         |
| +----+ +----+   +----+  |         | +----+ +----+   +----+  |
| |SC1 | |SC2 |.. |SC N|  |<=======>| |SS 1| |SS 2|.. |SS N|  |
| +----+ +----+   +----+  |         | +----+ +----+   +----+  |
|                         |         |                         |
+-------------------------+         +-------------------------+

## Primary Client - Primary Server Negotiation Phase

The two entities exchange a set of data to ensure the respective
identities.

They use HPKE KEM to negotiate a "SharedSecret".

## Primary Server / Client - Secondary Server / Client Registration Phase

The "SharedSecret" is shared securely:

-  By the Primary Client to all the Secondary Clients under its
   control.  The protocol to define this will be defined in a
   subsequent document.

-  By the Primary Server to all the Secondary Servers under its
   control.  The protocol to define this will be defined in a
   subsequent document.

## Secondary Client - Secondary Server communication

Each Client and Server derive a "SessionTemporaryKey" by using HPKE
KDF, using the following inputs:

-  The "SharedSecret".

-  The 5-tuple (SrcIP, SrcPort, DstIP, DstPort, Protocol) of the
   communication.

-  A Key Rotation Index (Kri).

The Kri SHOULD be initialized to zero.

The server and client initialize (separately) a pseudo-random non-
repeating sequence between 1 and 2^15-1.  How to generate this
sequence is beyond the scope of this document, and does not affect
the rest of the specification.  When the sequence is used fully, or
earlier if appropriate, the sender signals the other party that a key
change is necessary.  This is achieved by flipping the "F bit" and
resetting the PRSEQ.  The receiver increments the Kri of the sender,
and derives another SessionTemporaryKey to be used for decryption.

It shall be stressed that the two SessionTemporaryKeys used in the
communication are never the same, as the 5-tuple is reversed for the
Server and Client.  Moreover, the time evolution of the respective
Kri can be different.  As a consequence, each entity must maintain a
table with (at least) the following informations:

-  Flow 5-tuple, Own Kri, Other Kri

An implementation might optimize this further by caching the
OwnSessionTemporaryKey (used in Encryption) and
OtherSessionTemporaryKey (used in Decryption).

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
