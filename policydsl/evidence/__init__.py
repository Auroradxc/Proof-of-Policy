"""产物与可核验性：证书、签名密钥、回执链、锚定后端、核验入口。

这一层的共同点：产出的东西**离开本机也要能被第三方独立复算**
（`verifier` 是那条「只持公开产物」的路径）。

**本子包不 re-export 任何符号**，用法示例见 `docs/modules/03-certificate.md`
与 `docs/modules/04-anchoring-audit.md`。
"""
