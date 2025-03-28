# cross

Shadowsocks – the first and oldest one, pretty simple to deploy and use, but easily detectable by country firewalls.

Vmess – the first iteration of V2Ray family protocols, improving upon Shadowsocks legacy. Since 2020, considered not safe.

VLESS – the second iteration of V2Ray protocols, which only implements authentication, while XTLS is the encryption part. On the reddit and other places, many recommend deploying VLESS+XTLS-Vision which is considered the most reliable (citation needed).

Naive/Hysteria – unfortunately, couldn’t find much information about these…

ShadowTLS/Trojan – the most recent and (based on this paper – https://www.petsymposium.org/foci/2023/foci-2023-0002.pdf 22 ) the most sophisticated protocols. ShadowTLS is basically an extension to Shadowsocks, which is a huge plus for deployment. IMHO, this is the current king to bypass censorship.
