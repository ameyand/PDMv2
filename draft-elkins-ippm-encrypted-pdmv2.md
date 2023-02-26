---
title: "IPv6 Performance and Diagnostic Metrics Version 2 (PDMv2) Destination Option"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-elkins-ippm-encrypted-pdmv2-latest
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


## PDMv2 Introduction

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
