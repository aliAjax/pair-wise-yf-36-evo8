# 生物样本库知情同意与撤回

这是一个只使用Python标准库和SQLite的模块化项目，默认端口为`8302`。所有业务规则集中在`src/rules.py`，`app.py`只负责组装依赖和启动服务。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、数据结构、领域异常和基础校验。
- `src/rules.py`：状态机、权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务和乐观锁。
- `src/service.py`：用例编排、幂等处理、版本控制和审计写入。
- `src/http_api.py`：HTTP路由、请求解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8302
```

服务启动时会自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。

## 核心对象

- `participant`：参与者；`consent`：同意版本；`sample`：样本；`withdrawal`：撤回申请。
- `authorization`：正式代理授权，登记代理人（`agent_user_id`）、与参与者的关系（`relationship`）、可办理用途（`allowed_purposes`）和截止日（`expires_at`），创建即为 `active`，可 `revoke`。

## 正式代理授权

- 登记：`POST /api/authorizations`，可登记角色为 `admin`/`biobank`/`committee`；截止日不得早于当天，用途至少一项。
- 代理人提交同意：代理人（角色 `agent`）创建 `consent` 时携带 `authorization_id`。规则引擎核对代理人身份、授权是否仍为 `active`、截止日和用途范围；范围或日期不符一律退回并在错误信息中说明原因。员工（`admin`/`committee`/`biobank`）仍可不附授权直接登记同意。
- 激活复核：同意 `activate` 时再次核对授权状态、截止日和用途；代理人可激活本人代为提交的同意。
- 撤销：参与者本人（角色 `participant`，`X-User-Id` 为参与者ID）或登记角色对授权执行 `revoke`。尚未生效的 `draft` 同意在同一事务内被置为 `stopped`；已生效的同意和已入库样本保持原结论不变。
- 并发：撤销与同意激活同时发生时，由数据库写锁串行化，后拿到锁的一方收到 409 `ConflictError`，只有一方成功。
- 原子性：授权状态、同意状态和审计记录在同一个 `BEGIN IMMEDIATE` 事务中提交，任一步失败整体回滚。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/audit`：读取审计记录。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

样本销毁和外部机构调用是流程演示，不会自动删除真实存储中的样本。
