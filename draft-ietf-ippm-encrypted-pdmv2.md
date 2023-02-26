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

PDMv2 introduces confidential, integrity and authentication.

TBD


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

-  Primary (Writer) Client (WC): An authoritative node that creates
   cryptographic keys for multiple reader clients.

-  Primary (Writer) Server (WS): An authoritative node that creates
   cryptographic keys for multiple reader servers.

-  Secondary (Reader) Client (RC): An endpoint node which initiates a
   session with a listening port and sends PDM data.  Connects to the
   Primary (Writer) Client to get cryptographic key material.

-  Secondary (Reader) Server (RS): An endpoint node which has a
   listening port and sends PDM data.  Connects to the Primary
   (Writer) Server to get cryptographic key material.

Note: a client may act as a server (have listening ports).

-  Symmetric Key (K): A uniformly random bitstring as an input to the
   encryption algorithm, known only to Secondary (Reader) Clients and
   Secondary (Reader) Servers, to establish a secure communication.

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


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
