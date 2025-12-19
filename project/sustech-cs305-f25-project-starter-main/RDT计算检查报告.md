# RDT 计算检查报告

## 文档要求

根据 `docs/CS305-Fall2025-Project-Main.md` 的要求：

### Timeout Calculation 公式

- $\text{EstimatedRTT} = (1 - \alpha) \cdot \text{EstimatedRTT} + \alpha \cdot \text{SampleRTT}$
- $\text{DevRTT} = (1 - \beta) \cdot \text{DevRTT} + \beta \cdot |\text{SampleRTT} - \text{EstimatedRTT}|$
- $\text{TimeoutInterval} = \text{EstimatedRTT} + 4 \cdot \text{DevRTT}$

其中：$\alpha = 0.15$, $\beta = 0.3$

---

## 代码实现检查

### ✅ 1. 参数定义

**位置**: `src/peer.py:49-50`

```python
ALPHA = 0.15
BETA = 0.3
```

**检查结果**: ✅ **正确**
- `ALPHA = 0.15` ✓
- `BETA = 0.3` ✓

---

### ✅ 2. EstimatedRTT 计算

**位置**: `src/peer.py:1204`

```python
est = (1 - ALPHA) * prevEst + ALPHA * sampleRTT
```

**检查结果**: ✅ **正确**
- 公式：`(1 - α) · EstimatedRTT + α · SampleRTT` ✓
- 参数：`α = 0.15` ✓

---

### ✅ 3. DevRTT 计算

**位置**: `src/peer.py:1206`

```python
dev = (1 - BETA) * prevDev + BETA * abs(sampleRTT - est)
```

**检查结果**: ✅ **正确**
- 公式：`(1 - β) · DevRTT + β · |SampleRTT - EstimatedRTT|` ✓
- 参数：`β = 0.3` ✓
- 注意：代码中使用的是更新后的 `est`（EstimatedRTT），这是正确的

---

### ✅ 4. TimeoutInterval 计算

**位置**: `src/peer.py:1210`

```python
session.timeoutInterval = max(0.5, est + 4 * dev)
```

**检查结果**: ✅ **基本正确，但有额外限制**

**符合要求的部分**:
- 公式：`EstimatedRTT + 4 · DevRTT` ✓
- 计算：`est + 4 * dev` ✓

**额外限制**:
- `max(0.5, ...)` - 确保 timeout 至少为 0.5 秒
- 文档中**没有明确要求**这个限制
- 但这是一个**合理的实现细节**，防止 timeout 过小导致频繁重传

---

### ✅ 5. SampleRTT 采样

**位置**: `src/peer.py:859-861`

```python
if ack_num in session.sent_times:
    sample_rtt = max(0.0, now - session.sent_times[ack_num])
    self._rdt_update_rtt(session, sample_rtt)
```

**检查结果**: ✅ **正确**
- 在收到 ACK 时采样 RTT ✓
- 使用 `now - sent_times[ack_num]` 计算 SampleRTT ✓
- 使用 `max(0.0, ...)` 防止负值 ✓

---

### ✅ 6. 初始值处理

**位置**: `src/peer.py:1199-1202, 762-764`

```python
# 在 _rdt_update_rtt 中
if prevEst is None or prevEst == 0:
    est = sampleRTT
    dev = sampleRTT / 2.0

# 在创建 session 时
estimatedRTT=initial_timeout,  # 0.5
devRTT=initial_timeout / 2.0,   # 0.25
timeoutInterval=initial_timeout, # 0.5
```

**检查结果**: ✅ **合理**
- 初始值：`EstimatedRTT = 0.5`, `DevRTT = 0.25` ✓
- 第一次采样时：直接使用 `sampleRTT` 和 `sampleRTT / 2.0` ✓
- 这是标准的初始化方式

---

## 总结

### ✅ 符合文档要求的部分

1. ✅ **参数值正确**: `α = 0.15`, `β = 0.3`
2. ✅ **EstimatedRTT 公式正确**: `(1 - α) · EstimatedRTT + α · SampleRTT`
3. ✅ **DevRTT 公式正确**: `(1 - β) · DevRTT + β · |SampleRTT - EstimatedRTT|`
4. ✅ **TimeoutInterval 公式正确**: `EstimatedRTT + 4 · DevRTT`
5. ✅ **SampleRTT 采样正确**: 在收到 ACK 时计算

### ⚠️ 额外实现细节

1. ⚠️ **TimeoutInterval 最小值限制**: `max(0.5, ...)`
   - 文档中没有明确要求
   - 但这是**合理的实现细节**，防止 timeout 过小
   - **建议**: 如果测试要求严格遵循文档，可以考虑移除这个限制，或者确保初始值足够大

### 📝 建议

代码实现**基本符合文档要求**，公式计算完全正确。`max(0.5, ...)` 的限制是一个合理的实现细节，但如果测试要求严格遵循文档，可以考虑：

1. **保留限制**（推荐）：这是防止 timeout 过小的安全措施
2. **移除限制**：如果测试要求严格遵循文档公式，可以移除 `max(0.5, ...)`，直接使用 `est + 4 * dev`

---

## 验证

代码实现完全符合文档中的数学公式要求，RDT 计算逻辑正确。



