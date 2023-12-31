# mosproxy

一个 DNS 转发/代理软件。

- DNS over UDP/TCP/TLS/HTTP(S)/QUIC 协议互转。
- mTLS。
- 向上游发送 ECS (EDNS0 Client Subnet)。
- 基于域名的上游出站规则。
- 结构 log。可记录请求。
- 缓存。支持预取。支持使用 redis 作为二级缓存。支持按客户端地域的聚合缓存。
- prometheus metrics 统计。

更多说明见 wiki: https://irine-sistiana.gitbook.io/mosproxy-wiki/