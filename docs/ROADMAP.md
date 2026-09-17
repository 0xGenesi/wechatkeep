# 路线图（待办归档）

## 已归档待办

### ① DSL expected 通配/掩码 → branch-flip 配方化
现状：RecipeEngine 的 expected 门是静态字节，call/jump 的 rel32 逐构建不同，
"解析守卫翻转"类条目（fzlzjerry x64 silent 法，269574 = 0x5063F87 je→jmp）
无法用现有 DSL 表达。
方案：expected 支持 `XX??????XX:mask...` 通配语法（掩码思想已在 confirm 的
`bytes@+off:mask` 存在，扩展到 expected 即可）。
位点族已存档（269602 x64：isRevokemsg 9 调用者中 8 处 `test al,al; je +disp32`，
解析函数内 = 0x50a5634）。完成后：未来 x64 新构建获得第二条独立 silent 路径
（不依赖 isRevokemsg 函数存活）。

### ② 入口指纹纳入 archive 工具链
fzlzjerry 的研究脚本在导出函数时记录 12 字节入口指纹（供跨构建关联）。
落地：`contribute_expected.py --hashes` / archive_index.json 增加
`entry_fingerprints` 字段（addr + 前 12 字节），配合 watch-wechat 的自动定位
做"新构建 = 旧构建 + 指纹漂移比对"的快速预检。

## 新功能设计草案：自定义撤回提示（可选，默认关）

目标：用户自定义撤回提示文本，**不注入 dylib**（non-goal 不破）。

关键洞察：fzlzjerry 的 runtime-tip 需要 Runtime dylib 在运行时把短语对象写进
地址槽（返回运行时构造的 ObjC/C++ 对象）。但存在一条**纯静态路径**：

- Mach-O 的 `__DATA_CONST,__cfstring` 段存放编译期 CFString 常量——32 字节结构
  `{isa→__kCFConstantStringClassReference, flags=0x7C8, char*→__cstring, len}`，
  纯静态数据、无需运行时构造、天然是不可变 NSString（toll-free bridged）。
- 做法：在代码洞手工构建一个 CFString 常量（isa 指向镜像内既有的
  __kCFConstantStringClassReference 槽、flags 0x7C8、字符指针指向洞内自定义
  UTF-8 文本、长度字段），再把"提示文本消费点"的引用重指向该洞。
  x64 重写 lea rip-rel / arm64 重算 ADRP+ADD——均为静态字节。

前置研究（每构建一次，规模类比 keeptip2 攻坚）：
1. 定位提示文本消费/插入点（私聊：服务端 10000 消息 content 的落库/渲染；
   群聊：客户端生成的 replacemsg 路径）
2. 确认消费点字符串类型与所有权：NSString*/CFStringRef → CFString swap 可行；
   std::string（需构造语义）→ 标记不支持

已知风险与限制：
- CFString 常量是真对象（isa 合法、immortal），风险远低于 v7 的裸值——
  但仍须真机验证（v7 教训：任何"伪对象"都可能崩）
- 群聊：fzlzjerry 带完整运行时也在群聊失效（#63）——预期同样受限，先私聊
- 占位符 {from}/{time}/{content} 需运行时插值 → 静态方案只能整句固定文本

结论：可行、不违反 non-goal、可选项（默认关）。排期建议 v0.1.5 研究项，
不阻塞 v0.1.4。
