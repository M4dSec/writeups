# Writeup: Understanding the Importance of Finding a Server's Origin IP

# Summary

One of the initial challenges encountered during a penetration testing engagement is identifying the origin IP address of the target server. This write-up will show various methods and strategies to effectively determine the server's origin IP address.

# What does "origin IP" mean?

Many services today utilize various Content Delivery Network (CDN) providers, such as CloudFlare, Akamai, and Amazon CloudFront. These providers are designed to protect and support web servers by acting as reverse proxies, handling all incoming traffic.

This achieves several important objectives, including:

- **DDoS Protection:** CDNs offer protection against Distributed Denial of Service (DDoS) attacks by absorbing and mitigating the impact of malicious traffic.

- **Load Balancing:** CDNs distribute incoming traffic across multiple servers, preventing any single server from becoming overloaded and ensuring high availability and reliability.

- **Content Caching:** CDNs store copies of static content (such as images, CSS, and JavaScript files) on servers closer to users, thereby reducing latency and load times.

When you make an HTTP request to a domain, you are actually making a request to the CDN provider that the domain is using. This means you cannot retrieve the real server IP address.

# Why is this important?

Understanding the server's origin IP is crucial for accurately assessing vulnerabilities and potential security risks. This knowledge enables both threat actors and penetration testers to:

- Precisely map the network infrastructure and identify services operating on various IP addresses.
- Make direct HTTP requests that bypass CDN filtering mechanisms, potentially exposing multiple attack vectors.

# Techniques and Methods

The most effective that can an attacker do is looking for misconfigurations.
The application may inadvertently leak its server IP through various channels: exposed services on specific ports, custom HTTP headers, outdated DNS records, and numerous other avenues.

## Subdomains
Sometimes, some subdomain is not routed through the CDN and might expose the real IP address. This often includes mail servers, FTP servers, and other similar services.

## SSL-ceritifcates
SSL certificates provide another valuable avenue for discovering a server's origin IP address. When a server hosts an SSL certificate, various details about the certificate, including its public key, can be used to trace back to the original server, even when the server is behind a CDN. Tools like Censys and CRT.sh can help a lot with certificate analysys.


## DNS Records Analysis
By examining the DNS records of a domain, an attacker could potentially discover previously exposed IP addresses of the server from times when it was not behind a CDN. DNS records provide various types of information about a domain, and by analyzing these records, penetration testers can gather valuable insights that may lead to the discovery of the origin IP.

### Types of DNS Records
Different types of DNS records can reveal specific details about the domain and its infrastructure:

- **A Records:** These records map a domain name to an IPv4 address. By examining historical A records, one can find previous IP addresses that may have been used by the domain before switching to a CDN.

- **AAAA Records:** Similar to A records but for IPv6 addresses. Historical AAAA records can also provide information on previous IPv6 addresses.

- **MX Records:** Mail Exchange records specify the mail servers responsible for receiving email on behalf of the domain. Sometimes, these mail servers are not routed through the CDN, revealing the real IP address.

- **TXT Records:** Text records can contain various forms of information, including verification details for email services and other metadata. Occasionally, these records might inadvertently expose internal IP addresses or other sensitive information.

- **CNAME Records:** Canonical Name records alias one domain to another. By following the chain of CNAME records, it’s possible to uncover the origin domain that might point directly to the real server IP.

## Host Header Fuzzing
Even such things as `Host` header fuzzing using various subdomains and loopback IPs can occasionally bypass a CDN, enabling direct HTTP requests.

## WordPress Pingback 
In the case of WordPress, there is an interesting technique called `pingback` that sometimes allows an attacker to retrieve the real IP address of the server. For a detailed explanation, you can refer to this [excellent article](https://blog.nem.ec/2020/01/22/discover-cloudflare-wordpress-ip/).

## Social Engineering
Threat actors could  use diverse social engineering techniques to uncover real IP addresses. Methods such as phishing, pretexting, and even physical reconnaissance (like dumpster diving) can potentially yield valuable information.

# Useful tools
Two of the most effective and widely-used tools for IP discovering are Censys and Shodan. These tools comprehensively scan domains, gathering data on HTTP headers, SSL certificates, services operating on ports, metadata analysis, and more.

When examining DNS records, there are various tools available that can assist, such as SecurityTrails, DNSDumpster, and even VirusTotal.

# Ethical and Legal Considerations
It's essential to understand the ethical and legal implications of these techniques. Penetration testers must always have proper authorization before conducting any form of testing. Unauthorized access, enumerating or scanning can lead to legal consequences and damage to reputation.

# Conclusion

Identifying a server's origin IP is a critical step in understanding the underlying infrastructure and potential vulnerabilities of a target. While CDNs provide robust security and performance benefits, they also introduce challenges in directly accessing the server's IP. Through a combination of technical methods and tools, as well as social engineering tactics, penetration testers and threat actors alike can uncover this crucial information. It is essential to stay informed about these techniques to better protect and secure network environments against potential threats.
