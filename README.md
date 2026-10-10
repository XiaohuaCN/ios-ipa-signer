# iOS IPA 自动签名

使用 GitHub Actions macOS Runner 的 iOS IPA 重签名。

## 项目能力

- 在临时 Keychain 中导入 P12，并在任务结束后清理。
- 校验 IPA、描述文件、证书身份和 Bundle ID 的匹配关系。
- 按由内到外的顺序重签 App、Framework、dylib 和扩展。
- 重新打包 IPA，并输出 SHA-256 校验和及基础元数据。
- 支持由外部签名服务提交任务，Runner 只处理短期任务数据。

## 安全说明

签名材料只能通过 GitHub Actions Secrets 或受保护的外部服务传入，禁止提交到 Git 历史、Issue、Pull Request、workflow 输入或日志中。

不要在日志中输出完整请求体、下载地址、临时授权 URL、P12、描述文件、密码或访问令牌。仓库写入权限应仅授予可信维护者，因为能够修改工作流的人可能间接访问 Actions Secrets。

## 配置 Secrets

每套签名材料建议使用一组统一前缀，例如：

| Secret | 内容 |
| --- | --- |
| CERT_A_P12_BASE64 | P12 文件的 Base64 文本 |
| CERT_A_P12_PASSWORD | P12 密码 |
| CERT_A_PROFILE_BASE64 | 主 App 描述文件的 Base64 文本 |
| CERT_A_EXTRA_PROFILES_JSON | 可选的扩展、Watch 或 App Clip 描述文件数组 |

Base64 只是编码，不是加密。不要在终端、Issue 或日志中打印这些内容。超过 GitHub Secret 大小限制时，应使用受保护的外部存储或分片方案，不要截断材料。

## 运行

1. Actions 对应的签名工作流。
2. 手动运行并填写证书组、源文件标识和原始 IPA 的 SHA-256。
3. 运行完成后下载短期保留的 Artifact，并在授权设备上验证安装、启动及相关能力。

只有明确的手动或 API 触发才应执行真实签名；普通推送和 Pull Request 只运行不需要真实证书的检查。

## 签名限制

- 每个 App 或扩展必须有匹配且未过期的描述文件。
- P12 身份必须与描述文件及 Bundle ID 匹配。
- 工作流保留原始 Bundle ID，不自动改写 App 标识。
- App Store 描述文件不适用于直接安装分发；需要使用与设备或分发方式匹配的描述文件。
- 真实证书签名和真机安装验证仍需在受信任环境中完成。

## 本地验证

python3 -m unittest discover -s . -v

本项目的自动化测试用于检查输入校验、授权匹配和 ZIP 安全边界，不代替真实 Apple 签名及真机验收。
