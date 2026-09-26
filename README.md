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

- `participant`：参与者；`consent`：同意版本；`sample`：样本；`withdrawal`：撤回申请；`authorization`：代理授权。

## 代理授权

家属等代理人代签同意前必须先登记正式授权：

- `POST /api/authorizations`：登记`participant_id`、`agent_name`（代理人）、`relationship`（关系）、`purposes`（可办理用途列表）、`expires_at`（截止日，ISO日期，不得早于当天）。登记后状态为`active`。
- 代理人提交同意时在`consent`上携带`authorization_id`。创建和激活时系统都会核对：授权存在且为`active`、未过截止日、参与者一致、同意范围不超出授权用途。任一不符即退回，响应体`error`字段给出具体原因。
- `POST /api/entities/<id>/actions`，`action=revoke`：参与者撤销授权。同一事务内该授权下尚未生效（`draft`）的同意被置为`stopped`；已生效同意和已入库样本保持原结论不变。
- 撤销与同意激活并发时只允许一个成功：两者在同一`BEGIN IMMEDIATE`事务内通过乐观锁与状态守卫互斥，失败方收到`409`冲突，可重试。
- 授权状态、同意状态和审计记录在同一事务提交，任一失败整体回滚。

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
