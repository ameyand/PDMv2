---
title: "IPv6 Performance and Diagnostic Metrics Version 2 (PDMv2) Destination Option"
abbrev: "draft-ietf-ippm-encrypted-pdmv2"
category: std

docname: draft-ietf-ippm-encrypted-pdmv2-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 15
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

--- abstract

RFC 8250 defines an IPv6 Destination Option that carries Performance and
Diagnostic Metrics (PDM) such as sequence numbers and timing information.
While useful for measurement and troubleshooting, clear-text PDM data may
expose operational characteristics of endpoints and networks.

This document defines  PDMv2, a revised version of PDM that introduces a
registration-based security model. Instead of specifying cryptographic
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
registration-first architecture. Security-sensitive material is
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
- Maintain compatibility with the operational model of RFC 8250
- Avoid inline cryptographic handshakes at the IP layer
- Support heterogeneous transport protocols and non-transport flows
- Enable offline analysis by authorized entities
- Integrate cleanly with existing authentication and authorization
  infrastructures

# PDMv2 Foundational Principles

PDMv2 adheres to the following foundational principles:

{:req_p: counter="bar" style="format %d."}
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

# Registration Framework Overview

PDMv2 relies on an external registration system to establish trust and shared
context between participating entities.

## Registration Objectives

A PDMv2 registration mechanism establishes the context required for authorized endpoints and measurement systems to generate, receive, interpret, and, when applicable, decrypt PDMv2 information.

A registration mechanism is expected to provide:
* identification and authorization of participating endpoints or measurement domains;
* authorization to generate, receive, or analyze PDMv2 data;
* selection of the PDMv2 protection suite;
* establishment or provisioning of the keying material required by that suite;
* assignment of an Epoch value;
* definition of the scope and lifetime of the resulting security context;
* delivery of the context required to construct nonces and associated data; and
* procedures for expiration, replacement, and revocation of the security context.

This document does not require a particular registration protocol. Appendix A describes one possible mechanism.

## Registration Participants

The following logical roles are assumed:

{:req_rp: style="empty"}
-  Client : An endpoint that initiates communication and emits PDMv2 data
-  Server : An endpoint that receives communication and emits PDMv2 data
-  Authentication Server (AS) : A trusted entity that performs
  authentication and authorization
-  Analyzer : An authorized entity that interprets collected PDMv2 data



An implementation MAY combine roles within a single system.

## Registration Transport

The registration exchange MUST be protected by a secure channel. The choice
of transport and security protocol is out of scope for this document.

## Registration Output and SessionTemporaryKey

A successful registration produces a PDMv2 security context containing, at minimum:
* the identities or measurement domains to which the context applies;
* the authorization granted to each participant;
* the selected PDMv2 protection suite;
* an Epoch value;
* keying material or a directly provisioned SessionTemporaryKey;
* the scope and lifetime of the keying material; and
* the information required to construct nonces and associated data.

A SessionTemporaryKey is cryptographic keying material used to protect PDMv2 metric blocks during a bounded key epoch. It is derived or provisioned from keying material established by the applicable registration mechanism.

The registration mechanism or protection-suite specification MUST define:
* how the SessionTemporaryKey is derived or provisioned;
* the cryptographic algorithm and key length;
* the endpoints, flows, or measurement domain to which the key applies;
* the Epoch value associated with the key;
* the lifetime of the key;
* the rekey procedure;
* how authorized measurement systems obtain the required security context; and
* how expiration and revocation are handled.

When a SessionTemporaryKey is derived from a master secret, the derivation MUST use a cryptographically secure key-derivation function and a PDMv2-specific purpose label. The derivation MUST provide cryptographic separation between PDMv2 keys and keys used by other protocols or for other purposes.

A PDMv2 SessionTemporaryKey MUST NOT be a TLS, QUIC, IPsec, or other application or transport traffic key.

The specific registration protocol and key-derivation function are outside the scope of this document.

This document specifies the PDMv2 on-wire formats and the processing and exception-handling requirements for those formats. A registration mechanism supplies the security context described in this section but does not redefine receiver behavior for malformed, unauthenticated, or unauthorized PDMv2 options.

# PDMv2 Destination Options

## Use of IPv6 Destination Options

PDMv2 is carried as an IPv6 Destination Option within the Destination Options
Header as defined in RFC 8200. Processing rules from RFC 8250 continue to
apply unless explicitly updated by this document.

## Metrics

PDMv2 supports the following metrics:

{:req4: style="empty"}
- Packet Sequence Number (This Packet)
- Packet Sequence Number (Last Received)
- Delta Time Last Received
- Delta Time Last Sent
- Global Pointer



These metrics have the same semantics as in RFC 8250, with the addition of
the Global Pointer.

## Global Pointer

The Global Pointer provides a coarse indicator of packet transmission
activity by an endpoint. Separate counters are maintained for link-local
and global unicast source addresses.

# PDMv2 Destination Option

PDMv2 defines an unprotected wire format and a protected wire format. Both formats use the PDMv2 Option Type assigned by IANA.

PDMv2 does not reuse the PDM Option Type 0x0F assigned by RFC 8250. References in this document to fields adopted from RFC 8250 describe their semantics and do not indicate reuse of the RFC 8250 Option Type.

The Option Length distinguishes the unprotected and protected formats. A receiver can therefore determine from the PDMv2 option itself whether the metric block is protected. Registration context is required to decrypt and interpret a protected metric block, but it is not required merely to identify the format.

An implementation MUST NOT determine whether a received PDMv2 option is protected solely from local policy or registration context.

## Unprotected PDMv2 Format

~~~
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Option Type  | Option Len=22 | Version |        Epoch        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Packet Sequence Number This Packet             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Packet Sequence Number Last Received           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Global Pointer                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   ScaleDTLR   |   ScaleDTLS   |           Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Delta Time Last Received    |    Delta Time Last Sent       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

The Option Length is 22 decimal (0x16). As specified for IPv6 options, the Option Length excludes the Option Type and Option Length octets. The complete unprotected PDMv2 option occupies 24 octets.

The fields following the Option Length are:

| Offset | Length | Field |
|---|---|---|
| 2 | 4 bits | Version |
| 2 | 12 bits | Epoch |
| 4 | 4 octets | PSNTP |
| 8 | 4 octets | PSNLR |
| 12 | 4 octets | Global Pointer |
| 16 | 1 octet | ScaleDTLR |
| 17 | 1 octet | ScaleDTLS |
| 18 | 2 octets | Reserved |
| 20 | 2 octets | Delta Time Last Received |
| 22 | 2 octets | Delta Time Last Sent |

## Protected PDMv2 Format

The protected format uses an authenticated-encryption protection suite that produces a 16-octet authentication tag.

~~~
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Option Type  | Option Len=38 | Version |        Epoch        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Packet Sequence Number This Packet             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                  Protected Metric Block                       +
   |                       (16 octets)                             |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                   Authentication Tag                          +
   |                       (16 octets)                             |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

The Option Length is 38 decimal (0x26). It excludes the Option Type and Option Length octets. The complete protected PDMv2 option occupies 40 octets.

The plaintext protected metric block is:

~~~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Packet Sequence Number Last Received           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Global Pointer                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   ScaleDTLR   |   ScaleDTLS   |           Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Delta Time Last Received    |    Delta Time Last Sent       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

The protected format has the following organization:

| Offset | Length | Field | Protection |
|---|---|---|---|
| 0 | 1 octet | Option Type | Clear and authenticated |
| 1 | 1 octet | Option Length | Clear and authenticated |
| 2 | 4 bits | Version | Clear and authenticated |
| 2 | 12 bits | Epoch | Clear and authenticated |
| 4 | 4 octets | PSNTP | Clear and authenticated |
| 8 | 16 octets | Protected Metric Block | Encrypted and authenticated |
| 24 | 16 octets | Authentication Tag | AEAD output |

The Option Type, Option Length, Version, Epoch, and PSNTP fields MUST be cryptographically bound to the protected metric block as associated data.

This specification requires a 16-octet authentication tag. A future protection suite using a different tag length must define an unambiguous on-wire indication of its format and length.

## Option Type

The Option Type is the 8-bit value assigned by IANA for PDMv2:
TBD1

TBD1 is distinct from the PDM Option Type 0x0F assigned by RFC 8250.

The required IPv6 option action and change-en-route bits are reflected in the value assigned by IANA. The hexadecimal value remains TBD1 until the allocation is made.

## Version

The Version field is a 4-bit unsigned integer. This document defines Version 2.

A receiver that does not support the indicated version MUST process the option according to the action bits in the PDMv2 Option Type.

## Epoch

The Epoch field is a 12-bit unsigned integer identifying the PDMv2 security context and SessionTemporaryKey applicable to the protected option.

The Epoch value is a key selector. It is not secret keying material.

The registration mechanism or protection-suite specification MUST define how an Epoch is assigned, how long it remains valid, and how a receiver maps the Epoch to the applicable security context.

A sender MUST NOT independently protect different PDMv2 plaintext values using the same SessionTemporaryKey and nonce.

Before PSNTP reuse could cause nonce reuse with the same SessionTemporaryKey, the sender MUST establish a new key epoch or otherwise follow a nonce construction defined by the selected protection suite that prevents nonce reuse.

## PDMv2 Flow Identification

The term "PDMv2 flow" identifies the packet sequence and associated PDMv2 state. It is not limited to protocols that provide transport-layer port numbers.

For TCP and UDP, a PDMv2 flow is identified by:
* IPv6 source address;
* IPv6 destination address;
* upper-layer protocol number;
* source port; and
* destination port.

For ICMPv6, where transport-layer ports do not exist, a PDMv2 flow is identified by:
* IPv6 source address;
* IPv6 destination address;
* ICMPv6 Next Header value;
* ICMPv6 Type; and
* ICMPv6 Code.

For ICMPv6 message types containing an Identifier field, such as Echo Request and Echo Reply, an implementation SHOULD also use that Identifier to distinguish concurrent exchanges.

An ICMPv6 error message is classified using its outer IPv6 and ICMPv6 headers. The quoted packet carried inside the ICMPv6 error message does not identify the flow carrying the PDMv2 option.

For another upper-layer protocol without port numbers, the protocol specification or registration context SHOULD define an equivalent stable flow identifier. If no protocol-specific discriminator is available, packets having the same IPv6 source address, IPv6 destination address, and upper-layer protocol number are treated as one PDMv2 flow.

For TCP and UDP, the corresponding reverse-direction flow is identified by exchanging the source and destination IPv6 addresses and exchanging the source and destination ports.

For ICMPv6 request-and-reply message pairs, the corresponding reverse-direction flow exchanges the source and destination IPv6 addresses and associates the applicable request Type with its corresponding reply Type. When an Identifier field is present, the same Identifier is used for the association. A registration or protocol specification defining another request-and-reply relationship MUST define its reverse-direction mapping.

If no corresponding reverse-direction flow can be identified, PSNLR is initialized as specified by this document.

## Packet Sequence Number This Packet

The Packet Sequence Number This Packet field, abbreviated PSNTP, is a 32-bit unsigned integer.

PSNTP is initialized to a pseudorandom value when PDMv2 state is created for a flow. It is incremented modulo (2^{32}) for each packet processed as a new transmission at the PDMv2 sender's processing point.

PSNTP counts packet-processing events visible to the PDMv2 module. It does not count application data units, TCP sequence space, or unique transport payloads.

A TCP retransmission presented to the PDMv2 module as a new packet is a new transmission and receives a new PSNTP value.

Packets produced below the PDMv2 processing point by segmentation offload can retain the PSNTP value of the packet from which they were produced, as described in Section 7.12.

## Packet Sequence Number Last Received

The Packet Sequence Number Last Received field, abbreviated PSNLR, contains the PSNTP value from the most recently received PDMv2 observation associated with the corresponding reverse-direction flow.

Because segmentation, aggregation, packet duplication, reordering, or differences in processing location can affect the observations available to an implementation, PSNLR describes the most recent PDMv2 observation at the implementation's processing point. It does not necessarily identify the last physical packet received by an interface.

Before a PDMv2 option has been received for the corresponding reverse-direction flow, PSNLR is initialized to zero.

## Global Pointer

The Global Pointer identifies the applicable registration or measurement context. Its interpretation and allocation are defined by the registration mechanism.

The Global Pointer is not secret. A protected PDMv2 implementation MUST NOT treat possession of a Global Pointer as proof of authorization.

## Scale Fields and Delta Times

ScaleDTLR specifies the scale applied to Delta Time Last Received.

ScaleDTLS specifies the scale applied to Delta Time Last Sent.

Delta Time Last Received and Delta Time Last Sent are 16-bit unsigned values interpreted using their respective scale fields.

The existing scale and delta-time calculations inherited from the PDM model remain unchanged unless otherwise specified by this document.

## Reserved Field

The Reserved field is 16 bits.

A sender MUST set the Reserved field to zero. A receiver MUST ignore its value unless a future specification assigns meaning to these bits.

In the protected format, the Reserved field is part of the protected metric block.

## Segmentation and Aggregation Offload

PDMv2 can be implemented at a processing point preceding transmit segmentation or following receive aggregation. Consequently, the packets observed by a PDMv2 implementation do not necessarily have a one-to-one relationship with the IPv6 packets transmitted or received by a physical interface.

When a packet carrying PDMv2 is divided into multiple packets by TCP Segmentation Offload, Generic Segmentation Offload, or an equivalent mechanism below the PDMv2 processing point, the resulting packets MAY carry identical PDMv2 field values, including the same PSNTP.

Repeated PSNTP values resulting from such processing do not, by themselves, indicate packet loss, retransmission, malformed PDMv2 data, or nonconforming sender behavior.

Similarly, Generic Receive Offload, Large Receive Offload, or another receive-side aggregation mechanism can combine multiple received packets before they become visible to a PDMv2 implementation.

PDMv2 does not require an implementation to:
* disable segmentation or aggregation offload;
* inspect an outgoing interface's Maximum Transmission Unit solely for PDMv2 processing;
* update a PDMv2 option separately in each packet produced below the PDMv2 processing point; or
* reconstruct an exact one-to-one correspondence between PDMv2 observations and packets appearing on a physical interface.

A measurement or reconstruction system observing repeated PSNTP values SHOULD use other available information, including TCP sequence-number ranges, payload lengths, timestamps, IPv6 fragmentation information, and surrounding PDMv2 observations, to distinguish likely segmentation, duplication, retransmission, and reordering.

If the available information is insufficient to distinguish among these conditions, the system SHOULD report the result as ambiguous. It MUST NOT classify a repeated PSNTP as a protocol error solely because the value was repeated.

PDMv2 alone cannot always determine the exact number of IPv6 packets transmitted or received at a physical interface when segmentation or aggregation occurs outside the PDMv2 processing point.

## Protected Options and Repeated PSNTP Values

Multiple packets can contain the same protected PDMv2 value because of packet duplication or segmentation below the PDMv2 processing point.

Replication of an already protected PDMv2 option is not a new invocation of the authenticated-encryption algorithm. Repetition of an identical ciphertext and authentication tag therefore does not, by itself, constitute cryptographic nonce reuse.

A sender MUST NOT independently encrypt different PDMv2 plaintext values using the same SessionTemporaryKey and nonce.

A receiver or analyzer MAY recognize identical protected values as repeated observations. It MUST authenticate a protected value before using its contents, regardless of whether an identical value was previously observed.

## Receiver Validation and Exception Handling

A receiver MUST validate the PDMv2 Option Type, Option Length, Version, and format before interpreting dependent PDMv2 fields. A receiver MUST treat a protected PDMv2 option as invalid for PDMv2 processing if authentication fails, the indicated Epoch is unknown or expired, the required security context is unavailable, the sender is not authorized by that context, or the option is malformed or inconsistent with its declared format.

An invalid, unauthenticated, or unauthorized PDMv2 option MUST NOT be used for measurement, reconstruction, or updating PDMv2 state. Failure of a registration service or inability to obtain an applicable security context MUST fail closed with respect to protected PDMv2 content: the content MUST NOT be decrypted, interpreted, or used to update measurement state.

Unless local security policy requires otherwise, failure to process PDMv2 information SHOULD NOT cause the receiver to discard the enclosing packet's upper-layer payload. The receiver MAY ignore the PDMv2 information and continue normal IPv6 processing, subject to the processing behavior encoded in the IPv6 Option Type action bits.

A deployment MAY discard or block packets carrying invalid or unauthorized PDMv2 options when required by local security policy. Because such behavior can affect connectivity and can be exploited for denial of service, implementations SHOULD default to ignoring invalid PDMv2 measurement information rather than discarding the enclosing packet when the IPv6 Option Type action bits permit that behavior.

An unsupported Version MUST be processed according to the action bits in the PDMv2 Option Type. The receiver MUST NOT interpret the remaining fields using the Version 2 format.

A sender MUST set Reserved fields to zero. A receiver MUST ignore nonzero Reserved fields for protocol processing but MAY record the condition as an anomaly.

Implementations SHOULD count, log, or alert on authentication failures, unknown or expired Epoch values, unavailable security contexts, unauthorized senders, malformed options, unsupported versions, and other anomalous PDMv2 conditions. Such reporting SHOULD be aggregated or rate-limited to prevent logging-based denial of service.

Implementations SHOULD provide configurable policies for ignoring invalid PDMv2 data, generating an alert, discarding an enclosing packet, or blocking a source. The selected policy and its operational consequences are deployment-specific.

# Operational Model

## Registration Phase

Prior to sending PDMv2 data:


- The endpoint authenticates to an Authentication Server
- Authorization for PDMv2 usage is evaluated
- Shared secret(s) or credentials are provisioned

## Measurement Phase

- Endpoints send PDMv2 headers according to local policy
- No cryptographic negotiation occurs on the wire
- Intermediate devices forward packets unchanged

## Analysis Phase

- Authorized analyzers access collected data
- Interpretation uses registration-derived context

# Security Considerations

PDMv2 reduces exposure of sensitive operational metadata by ensuring that only
registered and authorized entities can meaningfully decrypt and interpret
protected measurement data.

This document intentionally does not specify cryptographic mechanisms or
ciphersuites. Security strength therefore depends on the chosen registration
system, its authentication methods, and its key management practices.

Authoritative receiver validation and exception-handling requirements are
specified in Section 7.14. This section summarizes the security rationale for
those rules:

*  Authentication and Authorization Failures:
   An attacker may attempt to inject fabricated PDMv2 options or forge metric
   data. To prevent forged, unauthenticated, or unauthorized PDMv2 options from
   contaminating measurement or reconstruction state, receivers MUST NOT use
   such data for metric calculations or PDMv2 state updates.

*  Unknown, Expired, or Unavailable Key Context:
   If an indicated Epoch is unknown or expired, or if the necessary security
   context cannot be retrieved, the receiver fails closed with respect to
   protected PDMv2 content. The protected metric block is not decrypted,
   interpreted, or used.

*  Nonce Reuse Prevention:
   Using the same SessionTemporaryKey and nonce to protect different plaintexts
   destroys AEAD cryptographic security guarantees. As specified in Section
   7.5, senders MUST rekey or follow suite-defined nonce construction to
   prevent nonce reuse under the same key before PSNTP space wraps.

*  Replication vs. Independent Encryption:
   As described in Section 7.13, replication of an already protected option by
   segmentation offload (TSO/GSO) or duplication is not a new AEAD encryption
   event and does not cause nonce reuse. However, receivers must authenticate
   each received option before using its contents.

*  Context Selectors vs. Secrets:
   The Global Pointer and Epoch fields are explicit key and context selectors;
   they are not secret and do not constitute proof of authorization. Possession
   of a Global Pointer or Epoch value MUST NOT be treated as proof of
   authorization.

*  Denial of Service via Packet Dropping:
   Dropping enclosing packets due to invalid or unauthenticated PDMv2 options
   creates a denial-of-service vector where on-path or off-path attackers can
   disrupt legitimate traffic by corrupting or attaching invalid options.
   Implementations SHOULD default to ignoring invalid PDMv2 information and
   continuing normal IPv6 processing of the packet payload, subject to the IPv6
   Option Type action bits.

*  Denial of Service via Logging and Alerts:
   Generating logs or alerts on every anomalous or invalid PDMv2 option could
   allow an attacker to exhaust system resources or logging storage.
   Implementations SHOULD aggregate or rate-limit anomaly reporting and alerts.

# Privacy Considerations

PDMv2 metrics may reveal traffic patterns or operational characteristics.
Registration-based authorization limits access to such data to approved
entities. Deployments SHOULD consider enabling PDMv2 on multiple flows to
reduce metadata distinguishability.

# IANA Considerations

## PDMv2 Destination Option

IANA is requested to assign a new IPv6 Destination Option Type for PDMv2 from the "Destination Options and Hop-by-Hop Options" registry.

| Value | Description | Reference |
|---|---|---|
| TBD1 | Performance and Diagnostic Metrics Version 2 | This document |

The PDMv2 allocation is independent of the PDM Option Type 0x0F assigned to RFC 8250. This document does not modify or redefine the RFC 8250 allocation.

The requested allocation must provide the option-processing behavior specified by this document. The final hexadecimal representation, including the action and change-en-route bits, will be inserted when IANA assigns the value.

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

# Example: RADIUS / EAP-Based Registration

This appendix illustrates one possible registration mechanism that can meet the registration objectives listed in Section 5.1 and provide the security context described in Section 5.4. The example is informative. Conformance with this document depends on satisfying the applicable normative requirements in the main body and does not depend on using RADIUS or EAP.


## Overview

This appendix describes an example registration system for PDMv2 based on
RADIUS with Extensible Authentication Protocol (EAP). This approach has been
implemented and validated in a prototype environment and demonstrates that
a shared master secret can be established prior to PDMv2 operation without
introducing inline cryptographic negotiation at the IP layer.

RADIUS and EAP are widely deployed for Authentication, Authorization, and
Accounting (AAA) in enterprise, service provider, and federated environments
(e.g., eduroam). Their use here is illustrative and leverages existing
infrastructure and operational experience.

## Participants

The following entities participate in this example:

-  PDMv2 Endpoint

   A Client or Server that will emit or receive PDMv2 data.
-  Authentication Server (AS)

   A RADIUS server that performs authentication and authorization using EAP.
-  Analyzer

   An authorized entity that may interpret or decrypt collected PDMv2 data
   using registration-derived context.

An implementation MAY combine multiple roles within a single system.

## Registration Flow (Example)

A typical registration flow proceeds as follows:


- Secure Channel Establishment
   The PDMv2 endpoint establishes a secure exchange with the Authentication
   Server. In many deployments this occurs implicitly as part of an EAP method
   protected by TLS (e.g., EAP-TLS or PEAP).

- Endpoint Authentication
   The endpoint authenticates using credentials appropriate to the deployment,
   such as certificates, credentials, tokens, or federated identity.

- Authorization Decision
   The Authentication Server determines whether the endpoint is authorized
   to:
   - Send PDMv2 data
   - Receive PDMv2 data
   - Participate in specific measurement domains

- Master Secret Establishment
   Upon successful authentication, EAP produces keying material (e.g., a
   Master Session Key). This keying material is made available to the endpoint
   and retained by the Authentication Server according to local policy.

- Provisioning of Context
   The endpoint associates the received master secret with local PDMv2 policy,
   such as permitted peers, scope, and lifetime.

- Analyzer Enablement (Optional)
   If offline analysis is required, the Authentication Server provisions
   appropriate authorization or keying context to approved analyzers.

## Registration Flow (Illustrative ASCII Diagram)

The following diagram illustrates the example flow. It is provided for
clarity only and does not define protocol behavior.

~~~
PDMv2 Endpoint              Authentication Server             Analyzer
|                              |                               |
|--- EAP Authentication -----> |                               |
|<-- EAP Success / Keys ------ |                               |
|                              |                               |
|   (Registration Complete)    |                               |
|                              |                               |
|====== PDMv2 Data Flow =====> |           (out of path)       |
|                              |                               |
|                              |------- Authorized Access ---->|
|                              |<------ Analysis Results ------|
~~~

## Use with PDMv2 Traffic

After registration:

- PDMv2 packets are sent without any inline authentication or negotiation.
- Endpoints locally derive any session-specific context needed to protect or
  interpret PDMv2 metrics.
- Intermediate routers forward packets without modification or inspection.
- Analyzers use registration-derived context to interpret collected data.

The registration system is not involved in the PDMv2 data path.

## Key Lifecycle Considerations

In this example, the RADIUS/EAP infrastructure can support:

- Periodic re-registration to refresh secrets
- Revocation of authorization by disabling credentials
- Federation across administrative domains
- Separation of endpoint and analyzer privileges

Specific key derivation, transformation, or protection mechanisms are
implementation-specific and intentionally outside the scope of this document.

## Example Deployment: Federated Environments (eduroam-Style)

In federated environments such as global research and education networks,
RADIUS is commonly deployed in a hierarchical or proxy-based architecture.
An endpoint authenticates using credentials issued by its home organization,
while authorization decisions may be enforced by visited or intermediate
domains.

This model maps naturally to PDMv2 registration:

- Endpoints authenticate using existing institutional credentials
- Authorization for PDMv2 usage can be scoped by domain, role, or policy
- Registration secrets are derived without requiring bilateral agreements
  between all participating domains

This example demonstrates that PDMv2 registration can scale across
organizational and administrative boundaries.

## Why TLS Session Keys Are Not Reused (Informative)

It may appear attractive to reuse TLS session keys for protecting PDMv2
metrics. However, this approach is not suitable for PDMv2 for several reasons:

-  Layering : PDMv2 operates at the IPv6 layer, while TLS is bound to
  transport-layer protocols such as TCP or QUIC.

-  Protocol Coverage : PDMv2 applies equally to UDP, ICMP, and other
  non-TLS-capable protocols.

-  Multiplicity of Flows : A single endpoint may emit PDMv2 data for
  multiple concurrent flows that do not share a common TLS session.

-  Analyzer Access : Offline analyzers may require access to PDMv2 data
  without participating in live TLS sessions.

-  Operational Simplicity : Registration decouples security establishment
  from traffic patterns and avoids inline negotiation complexity.

For these reasons, PDMv2 adopts a registration-based security model rather than
reusing transport-layer session keys.

## Summary

This appendix demonstrates that a RADIUS/EAP-based registration system can
satisfy the registration objectives and applicable normative requirements
defined in this document. The example shows that secure, scalable, and
federated registration can be achieved using existing AAA infrastructure,
without constraining PDMv2 to a specific authentication or cryptographic
technology.


# Change Log

Note to RFC Editor: if this document does not obsolete an existing
RFC, please remove this appendix before publication as an RFC.

# Open Issues

Note to RFC Editor: please remove this appendix before publication as
an RFC.
