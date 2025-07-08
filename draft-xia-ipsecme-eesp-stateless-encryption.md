---
title: "Stateless Encryption Scheme of Enhanced Encapsulating Security Payload (EESP)"
abbrev: "EESP Stateless Encryption"
category: std
submissionType: IETF
ipr: trust200902

docname: draft-xia-ipsecme-eesp-stateless-encryption-00
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true

# area: AREA
workgroup: IPSECME Working Group
keyword:
 - 
 - 
 - 
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
#  github: "ietf-ivy-wg/network-inventory-yang"
# latest: "https://ietf-ivy-wg.github.io/network-inventory-yang/draft-ietf-ivy-network-inventory-yang.html"

author:
  -
    name: Liang Xia
    org: Huawei Technologies
    email: frank.xialiang@huawei.com
  -
    name: Weiyu Jiang
    org: Huawei Technologies
    email: jiangweiyu1@huawei.com
 




contributor:


normative:



informative:
  PSP:
    title: PSP Architecture Specification
    author: 
    org: Google
    date: 
    target: https://github.com/google/psp/blob/main/doc/PSP_Arch_Spec.pdf
	
  UEC TSS:
    title: Ultra Ethernet Specification v1.0
    author: 
    org: Ultra Ethernet Consortium
    date: 
    target: https://ultraethernet.org/wp-content/uploads/sites/20/2025/06/UE-Specification-6.11.25.pdf

--- abstract

This draft first introduces several use cases for stateless encryption, analyzes and compares some existing stateless encryption schemes in the industry, and then attempts to propose a general and flexible stateless encryption scheme based on the summarized requirements. 

--- middle

# Introduction {#intro}

Recently, with the emergence of more new scenarios such as high-performance cloud services, AI large model computing, and 5G mobile backhaul networks, higher requirements have been put forward for the hardware friendliness, performance, and flexibility of the IPsec ESP protocol. A new protocol design, EESP {{?I-D.ietf-ipsecme-eesp}} {{?I-D.ietf-ipsecme-eesp-ikev2}}, is being discussed and formulated. EESP focuses on solving issues such as introducing more fine-grained sub-child-SAs, adapting the ESP header and trailer format, and allowing parts of the transport layer header to be unencrypted, and implementing flexible expansion of EESP new features through options.

In addition to the issues listed above that are being addressed, stateless encryption is also a very important point. Its basic idea is to dynamically calculate data keys based on a small number of master keys (for AES-GCM, the encryption key and authentication key are combined), which helps optimize hardware resource limitations, performance optimization, and key negotiation complexity in large-scale IPSec session scenarios. This draft first introduces several use cases for stateless encryption, analyzes and compares some existing stateless encryption schemes in the industry, and then attempts to propose a general and flexible stateless encryption scheme based on the summarized requirements.


# Use Cases


## General Computing of Cloud Service

Public cloud services provide IPSec VPN access for massive users, and the servers in their infrastructure need to support massive IPSec session access. If hardware supports IPSec, the hardware should support session-based encryption and decryption, and the data keys of different sessions are isolated. The server needs to maintain the security connection context between the server and a large number of clients, and the hardware with limited memory cannot store the huge context. Note that the client and server do not belong to the same trusted domain in this case.

The stateless encryption scheme in the {{PSP}} solution proposed by Google is used to address the above hardware memory overhead problem. Its main principle is to derive a data key based on the master key on the server side, and the client side obtains the data key through an out-of-band method. It has:

- Pros: Save half of total session contexts. Furthermore, since the master key is owned by server and not shared, key leakage affects only one server;

- Cons: When a large number of new sessions are created, the data key negotiation is along the out of band slow path in real time, the first packet transmit will be delayed, and which results in performance degrade.



## Cluster Communication in HPC Network
As shown in the below figure, encrypted communication is required between different instances of large-scale HPC jobs, the security session number is at the scale of O(M * N * N). So, an efficient security context management mechanism is required to solve the problem of large-scale security sessions. Note that all communication instances of a HPC job belong to the same trusted domain.

~~~

                           M Jobs
        +------------------------------------------+
        | +----------------------------------------+-+
        | | +--------------------------------------+-+-+
        | | |               Job 0                  | | |
        | | |  +---------+ +---------+ +---------+ | | |
        | | |  |Instance1| |Instance2| |Instance3| | | |
        | | |  +---------+ +---------+ +---------+ | | |
        +-+-+--------------------------------------+ | |
          +-+----------------------------------------+ |
            +------------------+-----------------------+
                               |
                               |Deploy Jobs
                               |to Server Cluster
                               |
+------------------------------V--------------------------------------+
|                        Server Cluster                               |
|                                                                     |
| +-----------+             +-----------+             +-----------+   |
| |+----------++            |+----------++            |+----------++  |
| ||+---------+++           ||+---------+++           ||+---------+++ |
| |||Instancei||| Ciphertext|||Instancej||| Ciphertext|||Instancek||| |
| |||  Keyi   ||<----------->||  Keyj   ||<----------->||  Keyk   ||| |
| +++---------+||           +++---------+||           +++---------+|| |
|  ++----------+|            ++----------+|            ++----------+| |
|   +----+------+             +-----------+             +-------+---+ |
|        |                    Ciphertext                        |     |
|        +------------------------------------------------------+     |
|                                                                     |
+---------------------------------------------------------------------+

							 

~~~
{: #fig-ipsecme-eesp-stateless-encryption-hpc title="Encrypted Communication for Large Scale HPC Networks"}

The stateless encryption scheme defined by {{UEC TSS}} can be used to solve the above problem. The main principle is that all communication instances of a HPC job belong to the same trust domain and share the same master key for both receiving and sending directions. It has:

- Pros:
  - Better than Google PSP，it saves all security session contexts; 
  - The communication parties do not need to store data keys, and the increase of the number of instances and connections of the HPC job does not affect the number of security contexts; 
  - Without out of band slow path data key negotiation, the first packet delay is small;
  - Data keys can be updated through the TSC.epoch.
- Cons:
  - Master key leakage affects the entire trusted domain;
  - The context content can be generated based on the SSI / Source IP / Destination IP field. Although the context content is flexible, the calculation overhead increases.


  
## NIC/DPU Pool for General Computing
To cope with large-scale traffic access (e.g., computing server access to storage networks) and efficiently utilize network card resources, NIC resource pooling is an effective solution. For north-south traffic from client access to servers, the NIC resource pool must be transparent to the application, allowing a client to access resources behind any NIC in the pool. When using encrypted connections, all NICs must share the same key for a client's access. At this point, the NICs in a resource pool belong to the same trust domain, so stateless encryption sharing the master key is applicable. This saves data key synchronization between NICs and reduces the storage of security sessions and data keys on them in scenarios with a large number of secure client connections. The client obtains the data key for this encrypted connection through an out-of-band method, which can be derived from the master key and context. Encrypted connections and contexts can be isolated based on flows or VM instances. As shown in the figure below:

~~~

                      VM Pool
+--------------------------------------------------+
|                                                  |
|       +----+  +----+  +----+  +----+             |
|       | VM |  | VM |  | VM |  | VM |             |
|       +----+  +----+  +----+  +----+             |
|                                                  |
|    +----------------------------------+          |
|    |                                  |          |
|    |  NIC pool with shared master key |          |
|    |       and security context       |          |
|    |   +-----+  +-----+     +-----+   |          |
|    |   | NIC |  | NIC | ... | NIC |   |          |
|    |   +---X\*  +-/-*-+     +---/++   |          |
|    |      / \ \\ /  |\       --/ |    |          |
|    +------/--\-/X\--+-\\-----//--+----+          |
+----------/---\/---\\+---\---/----+---------------+
           /   /\     \\-  \ /     |
          /   /  Ciphertext X\     |
          /  /    \-  |   \X  \    |
         / //  --- \  |  // \\ \   |
         // ---    \  | /     \\\\ |
        //--        \ |/        \\\|
   +--------+   +----\*--+   +----\|--+
   | client |   | client |   | client |
   +--------+   +--------+   +--------+


~~~
{: #fig-ipsecme-eesp-stateless-encryption-nic-pool title="Encrypted Communication for NIC Pool"}

Similarly, the NIC resource pool can also be used for east-west traffic access between VMs. In this case, all NICs are in the same security domain and can share a master key, and different data keys can be dynamically generated based on different encryption connection contexts.

## AI Computing




~~~

                +-----------------------------+
                |         Trusted Domain 1    |
                | +-----+ +-----+     +-----+ |
                | | CPU | | CPU | ... | CPU | |
                | +-----+ +-----+     +-----+ |
                | +-----+ +-----+     +-----+ |
                | | XPU | | XPU | ... | XPU | |
                | +-----+ +-----+     +-----+ |
                | +-----+ +-----+     +-----+ |
                | | XPU | | XPU | ... | XPU | |
                | +-----+ +-----+     +-----+ |
                ++----------+-----+----------++
                 |DPU/Switch|     |DPU/Switch|
                 +-----+----+     +------+---+
                       |   Global Trusted|Domain
       +---------------+-----------------+------------------+
 +-----+----+     +----+-----+       +---+------+    +------+---+
 |DPU/Switch|     |DPU/Switch|       |DPU/Switch|    |DPU/Switch|
++----------+-----+----------++     ++----------+----+----------+-+
| +-----+ +-----+     +-----+ |     | +-----+ +-----+     +-----+ |
| | CPU | | CPU | ... | CPU | |     | | CPU | | CPU | ... | CPU | |
| +-----+ +-----+     +-----+ |     | +-----+ +-----+     +-----+ |
| +-----+ +-----+     +-----+ |     | +-----+ +-----+     +-----+ |
| | XPU | | XPU | ... | XPU | |     | | XPU | | XPU | ... | XPU | |
| +-----+ +-----+     +-----+ |     | +-----+ +-----+     +-----+ |
| +-----+ +-----+     +-----+ |     | +-----+ +-----+     +-----+ |
| | XPU | | XPU | ... | XPU | |     | | XPU | | XPU | ... | XPU | |
| +-----+ +-----+     +-----+ |     | +-----+ +-----+     +-----+ |
|         Trusted Domain 2    |     |         Trusted Domain 3    |
+-----------------------------+     +-----------------------------+


~~~
{: #fig-ipsecme-eesp-stateless-encryption-ai-computing title="Encrypted Communication for AI Computing Network"}


# Requirement Summary

Based on the above use cases, the requirements for a general and flexible stateless encryption scheme are as follows:

- Support nodes within a trusted trust domain to share the same master key;
- Master key supports multi-level combination design. In a trust domain, the master key is composed of multiple root keys of different types and levels, such as trust domain root key, tenant root key, task group root key, etc. This enhances the overall security of the master key and supports fine-grained encryption traffic isolation (e.g., all nodes in a trust domain, nodes of the same tenant in a trust domain, nodes of the same computing task in a trust domain, etc.);
- Different types of root keys have different security levels and lifecycles, and corresponding key rotation mechanisms need to be defined.  The master key update will trigger the data key update;
- The key rotation of each type of root key should support multiple key rotations, such as pre_key, current_key, and next_key, to support rapid rotation while ensuring that real-time encryption and decryption are not affected;
- The key derivation of the data key is based on the master key, context, and KDF. KDF must support packet-by-packet data key calculation in most cases (except when the data key is cached in memory), which requires extremely high performance and must support cryptographically secure, hardware-concurrent high-performance algorithms;
- To support real-time derivation of the Data Key, context information and IV information need to be carried with the message. To support different scenarios and different granularities of data key calculation and encryption traffic isolation (based on stream, based on source IP, based on source ID, etc.), multiple combinations of context and IV need to be supported, and different combination algorithms need to be distinguished through specific fields in the message;
- Context information enables dynamic updates of the data key, such as carrying an epoch in the context. When the epoch changes, the data key is also refreshed accordingly;
- It is necessary to support encryption proxy capabilities across trust domains. At the edge nodes across trust domains (such as DPU, Switch, etc.), support for master keys and stateless encryption of two trust domains (local trust domain and global trust domain) is required, and proxy conversion of message encryption and decryption between the two trust domains must be completed.

# EESP Stateless Encryption Scheme
TBD.


# Security Considerations

TBD.


# IANA Considerations

TBD.


--- back



