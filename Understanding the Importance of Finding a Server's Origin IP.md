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

Understanding the server's origin IP is crucial for accurately assessing vulnerabilities and potential security risks. This knowledge enables both threat actors and penetration testers to precisely map the network infrastructure and identify all services operating on various IP addresses.
Additionally, it allows attackers to make direct HTTP requests that bypass the filtering mechanisms of CDNs, potentially exposing multiple attack vectors.

# Techniques and Methods

The most effective that can an attacker do is looking for misconfigurations.

The application may inadvertently leak its server IP through various channels: exposed services on specific ports, custom HTTP headers, outdated DNS records, and numerous other avenues.

Sometimes, some subdomain is not routed through the CDN and might expose the real IP address. This often includes mail servers, FTP servers, and other similar services.

By examining the DNS records of a domain, an attacker could potentially discover previously exposed IP addresses of the server from times when it was not behind a CDN.

In the case of WordPress, there is a technique called `pingback` that sometimes allows an attacker to retrieve the real IP address of the server. For a detailed explanation, you can refer to this [excellent article](https://blog.nem.ec/2020/01/22/discover-cloudflare-wordpress-ip/).

Even `Host` header fuzzing using various subdomains and loopback IPs can occasionally bypass a CDN, enabling direct HTTP requests.

# Useful tools

One of the most useful and most common tools out there is Censys and Shodan. This tools scan almost everything about the domain, including HTTP headers, SSL-certificates, services running on ports, metadata analysys and many other things.

When examining DNS records, there are various tools available that can assist, such as SecurityTrails, DNSDumpster, and even VirusTotal.

In the red team engagements threat actors can pull out the real IP with various social engineering techniques, such as fishing, pretexting and even dumpster diving.
