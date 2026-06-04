# TrustIX 文档

TrustIX 是一个基于根证书信任链、实时可信配置传播和 TC/eBPF 数据面的分布式 IX 路由交换系统。

当前文档入口：

- [完整项目蓝图](project-blueprint.md)：项目目标、核心能力、架构、控制面、数据面、安全模型、配置传播和路由器接入模型。
- [第一版运行方式](first-run.md)：当前后端骨架的启动、查询和已实现边界。
- [实现边界](implementation-boundaries.md)：当前 Go package 和命令入口的职责划分。
- [部署脚本](deployment-scripts.md)：稳定的 build/deploy/bootstrap 脚本接口和多网卡边界。
