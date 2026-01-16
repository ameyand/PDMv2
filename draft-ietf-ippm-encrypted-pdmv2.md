---
title: "IPv6 Performance and Diagnostic Metrics Version 2 (PDMv2) Destination Option"
abbrev: "draft-ietf-ippm-encrypted-pdmv2"
category: std

docname: draft-ietf-ippm-encrypted-pdmv2-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 13
area: "Transport"
workgroup: "Internet Engineering Task Force"
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
    country: United States
    organization: Inside Products, Inc.
    email: "nalini.elkins@insidethestack.com"

 -
    fullname: Michael Ackermann
    country: United States
    organization: BCBS Michigan
    email: "mackermann@bcbsm.com"

 -
    fullname: Ameya Deshpande
    country: India
    organization: NITK Surathkal/Google
    email: "ameyanrd@gmail.com"

 -
    fullname: Tommaso Pecorella
    country: Italy
    organization: University of Florence
    email: "tommaso.pecorella@unifi.it"

 -
    fullname: Adnan Rashid
    country: Italy
    organization: Politecnico di Bari
    email: "adnan.rashid@poliba.it"

 -
    fullname: Lorenzo Fedi
    country: Italy
    organization: University of Florence
    email: "lorenzo.fedi3@edu.unifi.it"

normative:
 RFC3552:
 RFC8250:
 RFC8200:

informative:
 RFC9180:
 RFC4303:
 RFC1421:
 RFC6973:
 RFC9288:

--- abstract

RFC 8250 defines an IPv6 Destination Option that carries Performance and
Diagnostic Metrics (PDM) such as sequence numbers and timing information.
While useful for measurement and troubleshooting, clear-text PDM data may
expose operational characteristics of endpoints and networks.

This document defines  PDMv2 , a revised version of PDM that introduces a
 registration-based security model . Instead of specifying cryptographic
algorithms or inline key negotiation, PDMv2 relies on a  prior registration
process  to authenticate entities, authorize participation, and establish
shared secrets. These secrets are then used by endpoints and authorized
analyzers to protect and interpret PDMv2 data according to local policy.

This document specifies the PDMv2 semantics, header structure, and operational
model. Cryptographic algorithms, key derivation functions, and cipher
negotiation are explicitly out of scope.

--- middle

# Introduction

The Performance and Diagnostic Metrics (PDM) Destination Option defined in
RFC 8250 provides packet sequence numbers and timing information to support
performance measurement and diagnostics. While effective, transmitting such
information in clear text can reveal details about endpoint behavior,
processing capability, and network characteristics.

PDMv2 enhances PDM by enabling secure operation through a
registration-first architecture . Security-sensitive material is
established out of band, prior to data transmission, and is not negotiated
inline with PDMv2 traffic. This approach preserves the lightweight nature of
PDM while avoiding tight coupling to transport-layer security protocols.

PDMv2 operates entirely at the IPv6 layer and applies uniformly to TCP, UDP,
ICMP, QUIC, and other upper-layer protocols. Intermediate devices are not
required to decrypt or interpret PDMv2 contents.

# Conventions used in this document

{::boilerplate bcp14-tagged}

# Design Goals

PDMv2 is designed with the following goals:

{:req_dg: style="empty"}

{: req_dg}

- Maintain compatibility with the operational model of RFC 8250
- Avoid inline cryptographic handshakes at the IP layer
- Support heterogeneous transport protocols and non-transport flows
- Enable offline analysis by authorized entities
- Integrate cleanly with existing authentication and authorization
  infrastructures

{: req_dg}

# PDMv2 Foundational Principles

PDMv2 adheres to the following foundational principles:

{:req_p: counter="bar" style="format %d."}

{: req_p}

- Registration-First Security:  All security context used by PDMv2 is
established during a prior registration phase. No cryptographic
negotiation occurs during PDMv2 packet exchange.

- IP-Layer Independence:  PDMv2 security does not depend on TCP, TLS,
QUIC, or any specific transport protocol.

- Minimal On-Path Impact:  Routers and intermediate nodes forward PDMv2
packets without decryption or inspection.

- Offline Decryption and Analysis:  PDMv2 data MAY be collected and
analyzed after transmission. Real-time interpretation is optional and
deployment-specific.

- Separation of Specification Scope:  This document defines protocol
behavior and data formats, not cryptographic algorithms.

- Explicit Authorization:  Only registered and authorized entities may
emit, receive, or analyze protected PDMv2 data.

{: req_p}

# Registration Framework Overview

PDMv2 relies on an external registration system to establish trust and shared
context between participating entities.

## Registration Objectives

A registration system used with PDMv2 MUST:

{:req_ro: style="empty"}

{: req_ro}

- Authenticate participating entities
- Authorize PDMv2 usage
- Establish one or more shared secrets or credentials
- Enable analyzers to interpret PDMv2 data
- Support revocation and lifecycle management

{: req_ro}

## Registration Participants

The following logical roles are assumed:

{:req_rp: style="empty"}

{: req_rp}

-  Client : An endpoint that initiates communication and emits PDMv2 data
-  Server : An endpoint that receives communication and emits PDMv2 data
-  Authentication Server (AS) : A trusted entity that performs
  authentication and authorization
-  Analyzer : An authorized entity that interprets collected PDMv2 data

{: req_rp}

An implementation MAY combine roles within a single system.

## Registration Transport

The registration exchange MUST be protected by a secure channel. The choice
of transport and security protocol is out of scope for this document.

# PDMv2 Destination Options

## Use of IPv6 Destination Options

PDMv2 is carried as an IPv6 Destination Option within the Destination Options
Header as defined in RFC 8200. Processing rules from RFC 8250 continue to
apply unless explicitly updated by this document.

## Metrics

PDMv2 supports the following metrics:

{:req4: style="empty"}

{: req4}

- Packet Sequence Number (This Packet)
- Packet Sequence Number (Last Received)
- Delta Time Last Received
- Delta Time Last Sent
- Global Pointer

{: req4}

These metrics have the same semantics as in RFC 8250, with the addition of
the Global Pointer.

## Global Pointer

The Global Pointer provides a coarse indicator of packet transmission
activity by an endpoint. Separate counters are maintained for link-local
and global unicast source addresses.

# PDMv2 Header Format

PDMv2 uses a single header format. Whether metric contents are protected
or unprotected is determined by local policy and registration context.

~~~
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Option Type  | Option Length | Version |        Epoch        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Packet Sequence Number (This)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Packet Sequence Number (Last)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Global Pointer                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  ScaleDTLR    |  ScaleDTLS    |           Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Delta Time Last Received    |    Delta Time Last Sent       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~


{:req7: style="empty"}

{: req7}

- Option Type

    0x0F

    8-bit unsigned integer.  The Option Type is adopted from RFC 8250 [RFC8250].

- Option Length

    0x22: Unencrypted PDM

    0x22: Encrypted PDM

    8-bit unsigned integer.  Length of the option, in octets, excluding the Option
    Type and Option Length fields.

- Version Number

    0x2

    4-bit unsigned number.

- Epoch

    12-bit unsigned number.

    Epoch field is used to indicate the valid SessionTemporaryKey.

- Packet Sequence Number This Packet (PSNTP)

    32-bit unsigned number.

    This field is initialized at a random number and is incremented
    sequentially for each packet of the 5-tuple.

    This field + Epoch are used in the Encrypted PDMv2 as the encryption
    nonce. The nonce MUST NOT be reused in different sessions.

- Packet Sequence Number Last Received (PSNLR)	 		
 		
    32-bit unsigned number.	 		

    This field is the PSNTP of the last received packet on the	 		
    5-tuple.

- Global Pointer	 		
 		
    32-bit unsigned number.

    Global Pointer is initialized to 1 for the different source
    address types and incremented sequentially for each packet with	 		
    the corresponding source address type.
 		
    This field stores the Global Pointer type corresponding to the
    SADDR type of the packet.

- Scale Delta Time Last Received (SCALEDTLR)

    8-bit unsigned number.

    This is the scaling value for the Delta Time Last Sent
    (DELTATLS) field.

- Scale Delta Time Last Sent (SCALEDTLS)

    8-bit unsigned number.

    This is the scaling value for the Delta Time Last Sent
    (DELTATLS) field.

- Reserved Bits

    16-bits.

    Reserved bits for future use.  They MUST be set to zero on
    transmission and ignored on receipt per [RFC3552].

- Delta Time Last Received (DELTATLR)

    16-bit unsigned integer.

    The value is set according to the scale in SCALEDTLR.

    Delta Time Last Received =
    (send time packet n - receive time packet (n - 1))

- Delta Time Last Sent (DELTATLS)

    16-bit unsigned integer.

    The value is set according to the scale in SCALEDTLS.

    Delta Time Last Sent =
    (receive time packet n - send time packet (n - 1))

# Operational Model

## Registration Phase

Prior to sending PDMv2 data:

{:req_om_rp: counter="bar" style="format %d."}

{: req_om_rp}

- The endpoint authenticates to an Authentication Server
- Authorization for PDMv2 usage is evaluated
- Shared secret(s) or credentials are provisioned

{: req_om_rp}

## Measurement Phase

{:req_om_mp: counter="bar" style="format %d."}

{: req_om_mp}

- Endpoints send PDMv2 headers according to local policy
- No cryptographic negotiation occurs on the wire
- Intermediate devices forward packets unchanged

{: req_om_mp}

## Analysis Phase

{:req_om_ap: counter="bar" style="format %d."}

{: req_om_ap}

- Authorized analyzers access collected data
- Interpretation uses registration-derived context

{: req_om_ap}

# Security Considerations

PDMv2 reduces exposure of sensitive operational metadata by ensuring that
only registered and authorized entities can meaningfully interpret
measurement data.

This document intentionally does not specify cryptographic mechanisms.
Security strength therefore depends on the chosen registration system, its
authentication methods, and its key management practices.

Implementations SHOULD support:

{:req_sc: counter="bar" style="format %d."}

{: req_sc}

- Key rotation
- Credential revocation
- Logging of anomalous PDMv2 behavior

{: req_sc}

# Privacy Considerations

PDMv2 metrics may reveal traffic patterns or operational characteristics.
Registration-based authorization limits access to such data to approved
entities. Deployments SHOULD consider enabling PDMv2 on multiple flows to
reduce metadata distinguishability.

# IANA Considerations

No new IANA actions are required by this document.

# Contributors

The authors wish to thank NITK Surathkal for their support and
assistance in coding and review.  In particular Dr. Mohit Tahiliani
and Abhishek Kumar (now with Google).  Thanks also to Priyanka Sinha
for her comments.  Thanks to the India Internet Engineering Society
(iiesoc.in), in particular Dhruv Dhody, for his comments and for
providing the funding for servers needed for protocol development.
Thanks to Balajinaidu V, Amogh Umesh, and Chinmaya Sharma of NITK for
developing the PDMv2 implementation for testing.


--- back


# Change Log

Note to RFC Editor: if this document does not obsolete an existing
RFC, please remove this appendix before publication as an RFC.

# Open Issues

Note to RFC Editor: please remove this appendix before publication as
an RFC.
