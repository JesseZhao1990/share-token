# 共享token

应用显示名统一为 `共享token`。主图标采用深玉绿色底色和相扣的薄荷绿、象牙白圆角 token，表达共享与连接。

- `app-icon.png`：1024 × 1024 透明背景原图，由 OpenAI 内置图像生成工具设计。设计提示：macOS 应用图标、深玉绿色圆角方形、两枚相扣的圆角 token、象牙白与薄荷绿、无文字、小尺寸清晰可辨。
- `app-icon.icns`：macOS 应用与 Dock 图标，包含 16–1024 像素各档分辨率。
- `tray-template.svg`：菜单栏用的单色矢量标记。
- `trayTemplate.png` / `trayTemplate@2x.png`：菜单栏 1x / 2x 模板图，自动适配系统明暗外观。

在 macOS 项目根目录运行 `node scripts/desktop-icons.mjs` 可从原始素材重新生成系统图标。打包时会校验显示名、图标内容和应用资源，避免退回 Electron 默认图标。

内部 bundle ID、可执行文件名和历史用户数据目录保持稳定，用户升级后仍可沿用原有连接与设置。ZIP 文件名保留 ASCII，解压得到 `共享token.app`。
