# test_06_adv_2.py 测试拓扑说明

## 一、Peer 配置信息

### 1.1 有 Chunk 的 Peer（8个）

| Peer ID | 地址 | Fragment文件 | 拥有的Chunks |
|---------|------|--------------|--------------|
| Peer 1  | 127.0.0.1:58001 | data6-1.fragment | **Chunk 1, 2** |
| Peer 2  | 127.0.0.1:58002 | data6-2.fragment | **Chunk 3, 4** |
| Peer 7  | 127.0.0.1:58003 | data6-3.fragment | **Chunk 5, 6** |
| Peer 14 | 127.0.0.1:58004 | data6-4.fragment | **Chunk 7, 8** |
| Peer 10 | 127.0.0.1:58005 | data6-5.fragment | **Chunk 9, 10** |
| Peer 15 | 127.0.0.1:58006 | data6-6.fragment | **Chunk 11, 13, 15** |
| Peer 12 | 127.0.0.1:58007 | data6-7.fragment | **Chunk 12, 14, 16** |
| Peer 13 | 127.0.0.1:58008 | data6-8.fragment | **Chunk 17, 18, 19, 20** |

### 1.2 没有 Chunk 的路由节点（7个）

**重要说明**：拓扑中还存在以下节点，它们**不持有任何chunk**，只作为路由节点参与数据包转发：

| Peer ID | 角色 | 说明 |
|---------|------|------|
| Peer 3  | 路由节点 | 仅转发数据包，不存储chunk |
| Peer 4  | 路由节点 | 仅转发数据包，不存储chunk |
| Peer 5  | 路由节点 | 仅转发数据包，不存储chunk |
| Peer 6  | 路由节点 | 仅转发数据包，不存储chunk |
| Peer 8  | 路由节点 | 仅转发数据包，不存储chunk |
| Peer 9  | 路由节点 | 仅转发数据包，不存储chunk |
| Peer 11 | 路由节点 | 仅转发数据包，不存储chunk |

**拓扑总节点数**：15个节点（8个有chunk + 7个路由节点）

---

## 二、下载任务 (DOWNLOAD Tasks)

### Task 1: Peer 1 下载 target1
- **下载者**: Peer 1 (127.0.0.1:58001)
- **目标文件**: target1.chunkhash
- **需要下载的Chunks**: **Chunk 4**
- **输出文件**: result1.fragment

**Chunk 4 的来源**:
- ✅ Peer 2 拥有 Chunk 4
- **请求路径**: Peer 1 → Peer 2 (请求 Chunk 4)

---

### Task 2: Peer 7 下载 target2
- **下载者**: Peer 7 (127.0.0.1:58003)
- **目标文件**: target2.chunkhash
- **需要下载的Chunks**: **Chunk 7, 12**
- **输出文件**: result2.fragment

**Chunk 7 的来源**:
- ✅ Peer 14 拥有 Chunk 7
- **请求路径**: Peer 7 → Peer 14 (请求 Chunk 7)

**Chunk 12 的来源**:
- ✅ Peer 12 拥有 Chunk 12
- **请求路径**: Peer 7 → Peer 12 (请求 Chunk 12)

---

### Task 3: Peer 10 下载 target3
- **下载者**: Peer 10 (127.0.0.1:58005)
- **目标文件**: target3.chunkhash
- **需要下载的Chunks**: **Chunk 11**
- **输出文件**: result3.fragment

**Chunk 11 的来源**:
- ✅ Peer 15 拥有 Chunk 11
- **请求路径**: Peer 10 → Peer 15 (请求 Chunk 11)

---

### Task 4: Peer 13 下载 target4
- **下载者**: Peer 13 (127.0.0.1:58008)
- **目标文件**: target4.chunkhash
- **需要下载的Chunks**: **Chunk 8, 16**
- **输出文件**: result4.fragment

**Chunk 8 的来源**:
- ✅ Peer 14 拥有 Chunk 8
- **请求路径**: Peer 13 → Peer 14 (请求 Chunk 8)

**Chunk 16 的来源**:
- ✅ Peer 12 拥有 Chunk 16
- **请求路径**: Peer 13 → Peer 12 (请求 Chunk 16)

---

## 三、完整的请求关系图

```
下载任务汇总:
┌─────────────────────────────────────────────────────────┐
│ Task 1: Peer 1 需要 Chunk 4                            │
│   └─→ 从 Peer 2 下载                                    │
├─────────────────────────────────────────────────────────┤
│ Task 2: Peer 7 需要 Chunk 7, 12                        │
│   ├─→ Chunk 7:  从 Peer 14 下载                        │
│   └─→ Chunk 12: 从 Peer 12 下载                        │
├─────────────────────────────────────────────────────────┤
│ Task 3: Peer 10 需要 Chunk 11                          │
│   └─→ 从 Peer 15 下载                                  │
├─────────────────────────────────────────────────────────┤
│ Task 4: Peer 13 需要 Chunk 8, 16                       │
│   ├─→ Chunk 8:  从 Peer 14 下载                       │
│   └─→ Chunk 16: 从 Peer 12 下载                        │
└─────────────────────────────────────────────────────────┘
```

---

## 四、Chunk 分布总览

### 按Chunk编号排序:
- **Chunk 1, 2**: Peer 1
- **Chunk 3, 4**: Peer 2
- **Chunk 5, 6**: Peer 7
- **Chunk 7, 8**: Peer 14
- **Chunk 9, 10**: Peer 10
- **Chunk 11, 13, 15**: Peer 15
- **Chunk 12, 14, 16**: Peer 12
- **Chunk 17, 18, 19, 20**: Peer 13

### 按Peer排序:
- **Peer 1**: Chunk 1, 2
- **Peer 2**: Chunk 3, 4
- **Peer 7**: Chunk 5, 6
- **Peer 10**: Chunk 9, 10
- **Peer 12**: Chunk 12, 14, 16
- **Peer 13**: Chunk 17, 18, 19, 20
- **Peer 14**: Chunk 7, 8
- **Peer 15**: Chunk 11, 13, 15

---

## 五、关键观察

1. **并发下载**: 多个peer同时进行下载任务，测试并发能力
2. **多源下载**: Peer 7 和 Peer 13 需要从多个peer下载不同的chunks
3. **路由节点**: 拓扑中包含7个**没有chunk的路由节点**（Peer 3, 4, 5, 6, 8, 9, 11），它们只负责转发数据包
4. **网络拓扑**: 拓扑文件 `topo6.map` 包含15个节点，其中8个有chunk，7个是纯路由节点
5. **测试重点**: 
   - 并发下载能力
   - 多源下载协调
   - 网络丢包处理（测试中会有packet loss）
   - 复杂拓扑下的路由和传输
   - **路由节点的数据包转发能力**

---

## 六、测试执行顺序

1. 启动所有8个peers
2. 发送DOWNLOAD命令：
   - Peer 1: DOWNLOAD target1
   - Peer 7: DOWNLOAD target2
   - Peer 10: DOWNLOAD target3
   - Peer 13: DOWNLOAD target4
3. 等待所有result文件生成（最多640秒）
4. 验证下载结果的正确性

---

## 七、验证检查点

测试会验证：
1. ✅ 所有result文件是否成功生成
2. ✅ 每个result文件是否包含目标chunk
3. ✅ 每个chunk的SHA1 hash是否匹配

