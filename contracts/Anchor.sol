// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Proof-of-Policy anchor registry（锚定登记合约）
/// @notice 把合规证书的摘要（`cert_digest` = 证书载荷的 SHA-256）登记到链上，
///         为「记录留存」提供一条公共、防篡改、带时间戳的存在性证明。
///
/// 设计取舍：
///   - **首次即最终**（first write wins）：同一 digest 只能登记一次，重复登记
///     回滚（`already anchored`）。这样链上时间戳不可被后来的提交者覆盖，
///     调用方重试时应先 `anchoredAt()` 查询。
///   - 只存 `bytes32` 摘要，**不存任何响应/策略内容**（隐私：证书内容留在链下，
///     链上只留下不可逆的承诺）。
///   - `anchoredAt(d) == 0` 表示「未登记」；区块时间戳从不为 0，该约定是安全的。
contract Anchor {
    mapping(bytes32 => uint256) private _ts;
    mapping(bytes32 => address) private _by;
    /// @notice 累计登记条数（等于 `seq` 的最后一个值）。
    uint256 public count;

    /// @param digest 证书摘要（bytes32）
    /// @param ts     区块时间戳（秒）
    /// @param by     提交者地址
    /// @param seq    本次登记的序号（从 1 开始）
    event Anchored(bytes32 indexed digest, uint256 ts, address indexed by, uint256 seq);

    /// @notice 登记一个证书摘要；同一摘要重复登记会回滚。
    function anchor(bytes32 digest) external {
        require(_ts[digest] == 0, "Anchor: already anchored");
        _ts[digest] = block.timestamp;
        _by[digest] = msg.sender;
        count += 1;
        emit Anchored(digest, block.timestamp, msg.sender, count);
    }

    /// @notice 返回登记时间戳；0 表示未登记。
    function anchoredAt(bytes32 digest) external view returns (uint256) {
        return _ts[digest];
    }

    /// @notice 返回登记者地址；未登记时为 0x0。
    function anchoredBy(bytes32 digest) external view returns (address) {
        return _by[digest];
    }

    /// @notice 摘要是否已登记。
    function isAnchored(bytes32 digest) external view returns (bool) {
        return _ts[digest] != 0;
    }
}
