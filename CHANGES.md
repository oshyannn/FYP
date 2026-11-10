# 第 3 部分：忘记密码（分步） + 请求帮助 + 去掉 “Enter reset code”

## A. 新增的文件
| 文件 | 作用 |
|---|---|
| Backend/scripts/setup_password_reset.py | 创建 `password_reset_requests` 表（一次性，可重复运行） |
| Backend/web/db_models/password_reset.py | 请求的读写、重置凭证（ticket）的发放和使用 |
| Backend/web/controllers/password_reset.py | 所有新接口和审批规则 |

## B. 替换的文件（直接覆盖仓库里的同名文件）
| 文件 | 改了什么 |
|---|---|
| Backend/web/web_setup.py | 注册新的 password_reset 蓝图（基于第 2 部分的版本） |
| DesktopApp/src/pages/auth/ForgotPassword.tsx | 改成分步：选择方式 → 输入邮箱 → 输入 6 位码（可 Resend，有 60 秒冷却）→ 设置新密码 |
| DesktopApp/src/pages/auth/UserLogin.tsx | 去掉 “Enter reset code”（基于第 2 部分的版本） |
| DesktopApp/src/pages/auth/StaffLogin.tsx | 去掉 “Enter reset code”（基于第 2 部分的版本） |

注意：UserLogin.tsx 和 StaffLogin.tsx 是在第 2 部分的基础上修改的，如果你之前没有应用第 2 部分，请先应用第 2 部分再应用这一部分。

## C. 操作顺序
1. 应用第 2 部分（如果还没有）。
2. 覆盖本部分的文件。
3. 在 Backend 目录、激活 Backend 的虚拟环境后运行：`python -m scripts.setup_password_reset`
4. 重启 `python app.py`。
5. 运行前端的构建检查（`npm run build`），把报错发给我。

## D. 规则（和你确认过的一致）
- user：可以自己验证（邮箱收码），也可以请求 employer 或 admin 帮忙。
- employer：只能请求 admin 批准。
- admin：只能请求另一位 admin 批准，批准人不能是自己。
- 忘记密码不需要 PIN。
- 请求只是“提交”，批准后才发码；批准人看不到码。
- 管理员手动发码（ManageUserModal 的 Send Password Reset Email）不受 user 的冷却限制。

## E. 还没做的（下一步）
- 审批页面：目前 `GET /api/staff/reset-requests` 和决定接口已经有了，但**还没有接入 Approvals 页面的界面**。需要 admin/employer 能在 Approvals 里看到并批准。这一步会改动 Approvals 相关的文件，等你确认后做。
- 旧的 `/api/auth/reset-password`（直接用 code 改密码）还保留着，没人使用，可以以后删除。
- ResetPassword.tsx 页面不再被忘记密码流程使用，但 App.tsx 还引用它，暂时保留。

## F. 验证状态（重要）
- 没有运行数据库脚本、没有启动后端、没有运行前端构建。
- 数据库和认证相关的代码都没有在真实环境中测试过。
- 第一次运行脚本或接口报错时，请把完整错误发给我。
