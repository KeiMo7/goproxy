# 多跳上游链（upstream chain）设计

## 目标
在不改变单跳行为的前提下，新增「多跳上游链 + 每跳独立认证 + 链路级失败语义」：
- 一条链由多个 Hop 组成，请求依次经过每一跳；每跳独立认证（none/basic/token/socks5 user/pass）
- 按目标域名（精确/后缀）或网段（CIDR）选择不同链路；链内跳序固定
- 跳间隧道混用：HTTP CONNECT、SOCKS5、HTTP 转发（forward 仅可作为末跳）
- 认证挑战（407 / SOCKS5 拒绝）定位到具体跳，仅针对该跳重试，不重发请求体
- 主链某跳不可达时按配置降级到备用链，全程可观测；全部失败时聚合每跳原因
- 隧道按「链+目标+凭据指纹」复用；凭据变化 → 指纹变化 → 新建
- 配置热更新：原子替换，在途连接不中断，新请求走新配置

## 包结构（github.com/elazarl/goproxy/upstream）
- types.go   ：Hop/Chain/Route/Config/Auth 等配置类型
- errors.go  ：HopError（跳级、分类、不含凭据）、RouteError（聚合）、FailoverReport
- socks5.go  ：最小 SOCKS5 客户端（协商/用户名密码/CONNECT/分类错误）
- chain.go   ：chainDialer —— 逐跳建链、407 跳级重试、隧道池、半开清理
- router.go  ：Router —— 路由匹配、降级编排、热更新、事件
- transport.go：RoundTripper/DialContext 适配（forward 末跳 vs 隧道末跳）

## 接入（根包 goproxy，零值不变）
- ProxyHttpServer 新增可空字段 `upstreamRouter`（通过 upstream 包的 Bind 注入，
  根包只依赖一个最小接口，避免 import 环）
- HTTP 路径：ctx.RoundTrip 优先走 upstreamRoundTripper；为 nil 时完全保持
  `ctx.Proxy.Tr.RoundTrip` 旧路径
- CONNECT 路径：connectDial 中优先走 router 的 DialContext；为 nil 时保持
  ConnectDialWithReq/ConnectDial 旧路径
- 不设置 router 时没有任何新代码介入，单跳配置与行为零变化

## 关键语义
1. 凭据隔离：每跳的 Auth 只在与该跳握手时使用，不写入转发请求头、不进日志/error；
   error 文本只含跳序号与跳名。测试用「认证回显代理」断言跨跳无泄漏。
2. 错误分类：FailureKind = unreachable / timeout / auth / refused / protocol / canceled。
3. 复用：cacheKey = chainID|fingerprint|target；fingerprint 含版本与凭据哈希（非明文）。
4. 半开：任一跳失败立即 close 当前 conn，失败隧道不入池；重试必然新建。
5. 降级：只发生在建链期（请求字节写出之前）；RoundTripper 再包一层 body 观察器，
   一旦请求体已被读取则禁止再次尝试，杜绝下游重复请求。
6. 热更新：atomic.Pointer 换 config；旧 chainDialer 保留到在途请求结束，仅关闭其空闲池。
