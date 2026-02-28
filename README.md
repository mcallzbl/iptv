# iptv

这是一个使用 Cloudflare Worker 提供静态 `IPTV.m3u` 的项目。

英文文档请看：[README.en.md](./README.en.md)

## 项目说明

- `GET /IPTV.m3u` 返回仓库内的播放列表内容。
- `GET /` 也会返回同一份播放列表（方便直接订阅）。
- 已启用 CORS（`Access-Control-Allow-Origin: *`）。
- 直播源选择上偏重辽宁地区本地频道，同时包含部分央视频道和卫视频道。

## 版权与使用声明

- 本仓库仅用于学习、测试与技术交流。
- 仓库本身不存储、制作或上传任何音视频内容。
- 频道名称、台标与节目内容版权归原权利人所有。
- 请在符合当地法律法规的前提下使用。
- 严禁用于商业传播或其他违法用途。
- 如有侵权内容，请通过 issue 提交，核实后将及时处理。

## 部署

1. 登录 Wrangler。
`pnpm dlx wrangler@latest login`
2. 部署 Worker。
`pnpm dlx wrangler@latest deploy`
3. 访问地址。
`https://<your-worker-subdomain>/IPTV.m3u`

## 绑定自定义域名

1. 打开 Cloudflare 控制台的 `Workers & Pages`，进入你的 Worker。
2. 在 `Settings` -> `Domains & Routes` 添加自定义域名（例如 `tv.example.com`）。
3. 之后可通过以下地址访问。
`https://tv.example.com/IPTV.m3u`

## 检查失效源

使用 Python 脚本检查 `IPTV.m3u` 中的源地址并生成报告。该检查会验证可播放性，不仅仅是 HTTP 状态码。

- 基础检查：
`python3 scripts/check_sources.py --input IPTV.m3u`
- 自定义报告路径：
`python3 scripts/check_sources.py --input IPTV.m3u --output reports/latest_invalid_report.md`
- 存在失效源时返回非零状态（用于 CI）：
`python3 scripts/check_sources.py --input IPTV.m3u --fail-on-invalid`
- 仅检查单条地址：
`python3 scripts/check_sources.py --check-url "http://example.com/live/index.m3u8"`
- 基于速度阈值排除卡顿源：
`python3 scripts/check_sources.py --input IPTV.m3u --probe-segments 4 --min-realtime-ratio 1.2 --min-single-realtime-ratio 0.9 --min-segment-kbps 800`

报告会包含频道名、源地址、源文件行号，以及该频道是否存在备用源。
