# annulus-proof · 年轮时间戳账本

每天一条公开记录，证明我（Yu）那天写下的笔记、计划和课堂记录**在那天已经存在，之后没被改过**。内容本身不公开，这里只有哈希、签名和时间戳。

One public entry per day proving that the notes, plans and lesson records I (Yu) wrote that day **existed by that day and have not been altered since**. The content is never published — only hashes, a signature and timestamps.

## 它证明什么 / What it proves

- **存在时间**：某个文件最晚在某个时间点就已经存在（由比特币区块 via OpenTimestamps 和 freetsa.org 的 RFC 3161 时间戳担保）。
  **Existence at time**: a file existed no later than a given moment (anchored in Bitcoin via OpenTimestamps, and by an RFC 3161 timestamp from freetsa.org).
- **完整性**：拿到原文件的人可以确认它和当天封存的字节一模一样。
  **Integrity**: anyone given the file can confirm it is byte-for-byte what was sealed that day.
- **连续、不可补写**：每天的哈希串在前一天后面，没内容的日子也有一条，所以不能事后插入或删掉一天而不被发现。
  **Continuity**: each day chains onto the previous one, empty days included, so a day cannot be inserted or removed later without breaking the chain.
- **同一把钥匙**：每条都由 `signing_key.pub` 对应的 ed25519 私钥签名。
  **Same key**: every entry is signed by the ed25519 key in `signing_key.pub`.

## 它不证明什么 / What it does NOT prove

- **不证明作者**：哈希只说明「这些字节在那时存在」，不说明是谁写的、有没有 AI 帮忙、内容是否真实。签名只说明是持有这把钥匙的人封存的。
  **Not authorship**: a hash shows the bytes existed, not who wrote them, whether AI helped, or whether they are true. The signature only shows the key holder sealed them.
- 不证明某天**没有**写别的东西（没被封进来的文件不在证明范围内）。
  Not that nothing else was written that day (unsealed files are outside the proof).
- 不证明内容的质量或意义。/ Nothing about quality or meaning.
- 时间戳只给「最晚」时间，不给「最早」时间。/ Timestamps give a latest time, not an earliest time.

## 怎么算 / How it is computed

```
leaf      = SHA-256(32-byte random salt || file bytes)          # 每个文件一片叶子，盐不公开
day_root  = Merkle root over the sorted leaves                    # 节点 = SHA-256(left || right)，落单的直接升一层
            (empty day: SHA-256(""))
day_hash  = SHA-256(prev_day_hash || day_root || "YYYY-MM-DD")   # 第一天 2026-11-01 的 prev = 32 个 0 字节
signature = ssh-keygen -Y sign -n annulus-proof  over the 64-char lowercase hex day_hash (no newline)
.ots/.tsr = OpenTimestamps / RFC 3161 timestamps over that same 64-char text
```

随机盐让别人没法靠猜内容来反推哈希。/ The salt stops anyone from confirming a guess about the content.

每天的文件 / Files per day: `proofs/YYYY-MM-DD.json` (`date, prev, day_root, day_hash, signature`), `.ots`, `.tsr`.

## 陌生人怎么验证 / How a stranger verifies

1. 整条链 + 签名 + 时间戳 / Whole chain, signatures and timestamps:

   ```bash
   pip3 install opentimestamps-client   # optional, for the Bitcoin check
   python3 verify.py chain
   ```

   OTS 刚封的几个小时显示 pending，比特币确认后会变成完整证明。
   A fresh `.ots` shows *pending* for a few hours until Bitcoin confirms it.

2. 某个文件 / One file — I give you the file plus a small disclosure JSON (`date`, `salt`, Merkle `path`):

   ```bash
   python3 verify.py file the_file.md disclosure.json
   ```

   它算 leaf → 沿路径算到 day_root，和那天公开的 day_root 对比；再用第 1 步确认那天的 day_hash、签名和时间戳。
   It computes the leaf, walks the path up to the day_root and compares it with that day's public entry; step 1 then confirms that day's hash, signature and timestamps.

手动做也可以 / By hand:

```bash
printf %s "<day_hash>" > day_hash
ssh-keygen -Y verify -f allowed_signers -I annulus-proof -n annulus-proof -s sig.txt < day_hash   # signature from the JSON
ots verify -f day_hash proofs/YYYY-MM-DD.ots
openssl ts -verify -data day_hash -in proofs/YYYY-MM-DD.tsr -CAfile tsa/cacert.pem -untrusted tsa/tsa.crt
```

`tsa/` 里是 freetsa.org 的公开证书 / freetsa.org's public certificates.
