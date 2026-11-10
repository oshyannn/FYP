# 星标 (Saved URLs) + Always block 修复

## 原因
`Backend/web/web_setup.py` 没有注册 `saved_urls` 和 `site_rules` 两个蓝图，所以 `/api/saved-urls`、`/api/site-rules` 一直返回 404。
数据库表 `saved_urls`、`url_lists` 已经存在，不用改数据库。

## 改了什么
| 文件 | 内容 |
|---|---|
| Backend/web/web_setup.py | 注册两个蓝图；CORS 方法加上 PUT |
| DesktopApp/src/pages/user/SavedUrls.tsx | 新：Saved URLs 页面 |
| DesktopApp/src/pages/user/SiteRules.tsx | 新：Site Rules 页面 |
| DesktopApp/src/pages/user/UserApp.tsx | 接入两个新页面 |
| DesktopApp/src/components/layout/nav.ts | 侧边栏加 Saved URLs、Site Rules |
| DesktopApp/src/App.tsx, DesktopApp/src/types.ts | 扩展可以打开 saved / sites 页面 |
| file_structure.md | 更新文件结构 |

## 操作顺序
1. 覆盖文件（按相同路径）。
2. 重启后端：`python app.py`
3. `Extension/ui` 里运行 `npm run build`，再在 chrome://extensions 重新加载扩展。
4. `DesktopApp` 里运行 `npm run build`，把报错发给我。

## 验证状态
没有运行后端、没有 build 前端，也没有在浏览器里测试过。
