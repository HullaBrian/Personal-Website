---
layout: post
title: Common Pitfalls in Network Security
subtitle: "Some Do's and Don'ts at the Network Level"
thumbnail-img: /assets/img/sinkhole.jpg
share-img: /assets/img/sinkhole.jpg
author: Jonathan Beierle
tags: ["Network Security"]
---

The security of an organization's network is one of the most important things to prioritize.
It's crucial that it's confidentiality, integrity, and availability are maintained. However,
one of the most common security failures within an organization is its network security, despite
the potential impact of a network security incident. Even though there are many ways to fall
into a pit when it comes to network security, hope is not lost, thankfully. This blog post
aims to bring light to some common pitfalls when it comes to organizational network security.

- [Network Device Misconfigurations](#network-device-misconfigurations)
    - [Weak Credentials](#weak-credentials)
    - [Insecure Protocols and Encryption](#insecure-protocols-and-encryption)
    - [Access Controls, What Access Controls?](#access-controls-what-access-controls)
        - [Least Privilege](#least-privilege)
        - [Network Access Control (NAC)](#network-access-control-nac)
- [Provisioning and Segmentation Issues](#provisioning-and-segmentation-issues)
    - [VLAN's...What're Those?](#vlanswhatre-those)
    - [Addresses Addresses Everywhere, Not Any Bit Distinct](#addresses-addresses-everywhere-not-any-bit-distinct)
- [General](#general)
    - [Storing Passwords in Insecure Places](#storing-passwords-in-insecure-places)
    - [Updates People, Updates!](#updates-people-updates)
    - [What's a Documentation?](#whats-a-documentation)
    - [Limited Device and Network Visibility](#limited-device-and-network-visibility)
    - [Too Complex](#too-complex)
    - [Security Devices, but Where's the Training?](#security-devices-but-wheres-the-training)
- [Conclusion](#conclusion)

# Network Device Misconfigurations
What makes up the network? Well, to put it simply, you have network devices, and you have
endpoints. While everyone and their cat is focussing on endpoint security, it's very easy
to overlook some commnon network device misconfigurations.

## Weak Credentials
Everyone always says it, but having weak credentials is a really good way to let somebody
into the network that isn't supposed to be. Ensure that all credentials used to login to 
devices follow a couple guidelines:
- Minimum 12 characters in length
- Complex (mix of upper and lowercase letters, numbers, and special characters)
- Is NOT easily guessable if someone knows attributes of you or your organization
    - Example: If your organization's name is `DEVCORP`, don't make a password `D3vC0Rp!`

## Insecure Protocols and Encryption
Something not often thought of is what protocols are being used in the network. Protocols 
are the key to allowing device communication within a network, so ensuring that only secure
protocols are used should be high priority for any organization.

Below is a table for general recommendations for network protocols. However, depending on
business operational requirements, protocols such as NTLM may be required for compatability
reasons. As such, use your best judgement when determining what protocols to allow on your
networks.

| Do                            | Do Not                 |
|-------------------------------|------------------------|
| SMBv3                         | SMBv1, SMBv2           |
| Kerberos (NTLMv2 if required) | NTLM (at least NTLMv1) |
| HTTPS                         | HTTP                   |
| SNMPv3                        | SNMPv1, SNMPv2         |
| SSHv2                         | SSHv1, Telnet          |
| SFTP, FTPS                    | FTP, TFTP              |
| LDAPS                         | LDAP                   |

In general, organizations should steer clear of protocols that offer insecure, little, or no
encryption. It's up to the organization to determine what risks they're willing to undertake.
While the protocols mentioned above are generally good ideas to implement, they aren't silver
bullets. For example, attackers can still use Kerberos for lateral movement inside an Active
Directory environment.

In general, however, I'd recommend completely abstaining from the following protocols
- LLMNR
- mDNS
- NetBIOS

## Access Controls, What Access Controls?
Access controls are extremely important within any organization, but how does it apply to network
security? Well, as the name suggests, you're controlling access to resources on the network! One
thing to keep in mind, however, is that it's all a balancing act - you have to ensure that those
who need access have it, and those who don't need access don't. Furthermore, how difficult it is
to access a system is important. Sure, having 4 different forms of authentication would make it 
more difficult for an attacker to access a system, but it also hinders the speed at which authorized
access is attained.

### Least Privilege
The principle of least privilege is one of the most important things to implement to keep a network
secure. Dave in accounting should not be able to use his account to log into network devices and make
configuration changes. Thus, ensuring that only a select few people are able to access specific network
resources should be highly prioritized.

### Network Access Control (NAC)
Network Access Control (NAC) is an extremely potent tool in an organization's network security toolbox.
As Cisco puts it in their [post](https://www.cisco.com/c/en/us/products/security/what-is-network-access-control-nac.html)
regarding NAC:
```
A NAC system can deny network access to noncompliant devices, place them in a quarantined
area, or give them only restricted access to computing resources, thus keeping insecure nodes from infecting
the network.
```

Thus, having these controls significantly increases network security simply by allowing granular
control over what is allowed to access it. If there's a compromised endpoint, having the ability
to quarantine it can prove to significantly hinder an attacker's ability to penetrate the network and grant precious time to defenders.


# Provisioning and Segmentation Issues
With everything said, probably one of the best way to prevent attackers from laterally moving in a
network is simply to segment it - whether that be through VLANs, air gapping, or something else.

## VLAN's...What're Those?
Although Virtual Local Area Networks (VLANs) were first described in 1998, they are still one of -
if not - the most common method to segment a network. Don't think that putting everything on one
vlan will save you from a potential attack, however. Using VLANs still requires thought into how
a network should be broken up into logical chunks. For example, it's common to split a network into
pieces based off of use-case. There might be vlans for POS, IOT, and even guest devices!

One thing that I would strongly advise when it comes to thinking out what VLANs to have is to
ensure that device management interfaces are put onto their own seperate VLAN. As an example,
having a VLAN specifically so that you can manage your switch management interfaces can be crucial
to ensuring a secure network environment.

## Addresses Addresses Everywhere, Not Any Bit Distinct
![alt text](/assets/img/ocean.jpg)

Subnetting is one of the first things taught in any network class, and is a foundational concept in
any good network. You may be asking, why is this being talked about to secure a network? Well,
first off, as you may know from your networking classes, unless it's configured to, devices in
different subnets can't communicate with each other (at least at layer 3). While this is a fairly
trivial control to get around, it can prove to hinder adversarial advances into a network.

As previously stated, subnetting is a relatively weak security control. However, one thing that
subnetting does really well is allowing defenders to better understand the context of a device
given an IP address. If an organization has an IP addressing scheme that incorporates information
into the address, then just having an IP address of a compromised host may greatly assist in
defensive action. For example, it is relatively common to include information such as a physical
location ID or VLAN ID into an octet of an IP address to better distinguish it from others. While
technologies such as DNS allow for translations of IP addresses into common names, the more
information that can be determined from small pieces of information is vital to quick response.
Furthermore, DNS can only translate IP address into common names such as translating `192.168.1.1`
into `FW-1.local`. Should an organization include VLAN IDs into an IP address, having `192.168.10.1` would allow a defender to immediately recognize the originating VLAN for a potential attack.

# General
## Storing Passwords in Insecure Places
![alt text](/assets/img/sicilian-dies.webp)

Perhaps one of the oldest tricks in the book when it comes to a network compromise is storing
credentials in an insecure place. Do NOT have a `passwords.txt` files with the password for
anything! One suggestion for solving this issue is to use a trusted password manager to store
credentials. Although this will solve the glaring insecurities of insecure credential
placement, it will not save you from one of the weakest links in cyber security - people.
Having proper user training is vital to bettering organizational security posture.

## Updates People, Updates!
A very low hanging fruit when it comes to network security is ensuring that devices connecting
to or facilitating the network are properly updated. That isn't to say that you need to
immediately update a device as soon as an update comes out, however, as it is not unheard of
for software developers to push faulty updates leading to a whole host of problems.

Ultimately, it is up to the organization to determine what policy they want to have for pushing
updates to devices. Having the latest security patch applied as soon as possible may be the best
choice for an organization, while some may choose to wait until updates are proven to work in 
customer environments.

## What's a Documentation?
Writing documentation is useless, right? After all, we have John Doe who's been here for 30 years
and he knows everything! Well, John Doe may be a good source of information, but if something
happens to him, nobody may know enough to maintain critical business operations. Suddenly John's
"duck tape and superglue" approach isn't working anymore, and nobody has any idea how to fix it.
Well, that's why documentation is so vital. Having a centralized knowledge base is so
important within an organization, especially for storing environment-specific information. Despite
what is commonly said, you're not going to find everything on the internet, so when something
happens to your environment, it's important to have specific documentation to hopefully fix it.

Now, how does that relate to network security? Well, having documentation may not necessarily
help much in terms of active security posture, but it can significantly assist defenders in
having all of the details of the network at their disposal in the event of an incident. In fact,
one of the biggest advantages that defenders should have over a given adversary is knowledge
regarding all of - if not - most of the network. This can be achieved through proper
documentation.

## Limited Device and Network Visibility
![alt text](/assets/img/no-visibility.gif)

One of the worst things that can happen to an organization in terms of responding to an incident
is when they have little to no visibility into what's going on with their network or network
devices. Thankfully, there's a lot that can be done to solve this glaring issue. Below is a list
of possible solutions to gain increased insight into network/device activities:
- SNMP monitoring (Use SNMPv3 please!)
    - Uptime
    - Temperature
    - Interface errors and throughput
    - CPU utilization
    - Memory usage
- Logging
    - Configuration and state changes
    - Login and logoff events

I would also strongly recommend using some sort of SIEM or log aggregation solution to
better aggerate and search through logs generated by network devices. Here are a few examples
- Elastic
- Splunk
- Graylog

Lastly, having a way to easily create a security dashboard for your network devices can provide
a great way to visually monitor network devices at scale. For this I would recommend using tools
like Prometheus and Grafana.

## Too Complex
Once you learn a lot about networking it's very easy to fall into the trap of overcomplicating a
network. Remember, you may be trying to secure a network, but you're also supporting business
operations, so balance is crucial. Sombody may say that they want a gigantic network complete with
SDWAN, EIGRP, BGP, and HSRP, but that may be too complicated for the organization, and thus places
a greater strain on the network and security team(s). There may not always be a choice, but please
do your best to balance simplicity, complexity, and security to best secure business operations.

## Security Devices, but Where's the Training?
"We spend $500,000 dollars on AI driven security appliances! How did we still get hacked?"

One of the worst pitfalls in network security is to not train the people who are defending your
network. Even though security appliances these days tend to be very good at what they do, having
people skilled enough to use them is just as - if not - more important that the security
appliances themselves. Investing in properly educating employees on the tools being used in the
organization's environment is crucial to having an excellent security posture.

# Conclusion
Network security remains one of the most important areas of security. Although I've provided a
lot of general recommendations for network security, it's still up to you to decide how you want
to go about implementing them.

Remember, balance is key when it comes to implementing these.
