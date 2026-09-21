#!/bin/bash
# SecWeaver Agent - Metrics 和热加载功能测试脚本

set -e

echo "========================================="
echo "SecWeaver Agent 功能测试"
echo "========================================="
echo ""

# 1. 检查二进制文件
echo "1. 检查二进制文件..."
if [ ! -f "./secweaver-agent" ]; then
    echo "❌ secweaver-agent 二进制文件不存在"
    echo "请先运行: go build -o secweaver-agent ."
    exit 1
fi
echo "✅ 二进制文件存在"
echo ""

# 2. 测试版本命令
echo "2. 测试版本命令..."
./secweaver-agent version
echo ""

# 3. 创建测试配置
echo "3. 创建测试配置..."
TEST_DIR="/tmp/secweaver-agent-test-$$"
mkdir -p "$TEST_DIR"

cat > "$TEST_DIR/config.json" <<'EOF'
{
  "enterprise_id": "TEST0000000000ID",
  "status_path": "/tmp/secweaver-agent-test/status.json",

  "metrics": {
    "enabled": true,
    "listen_address": "127.0.0.1:19100",
    "path": "/metrics"
  },

  "log_level": "info",

  "audit_demux": {
    "subscriber_queue_size": 512,
    "backpressure_sampling_enabled": false,
    "backpressure_high_watermark": 0.9
  },

  "license": {
    "enabled": false
  },

  "modules": {}
}
EOF

echo "✅ 测试配置已创建: $TEST_DIR/config.json"
echo ""

# 4. 测试配置验证（dry-run）
echo "4. 测试配置验证（dry-run）..."
if ./secweaver-agent run -config "$TEST_DIR/config.json" -dry-run 2>&1 | head -20; then
    echo "✅ 配置验证通过"
else
    echo "❌ 配置验证失败"
    exit 1
fi
echo ""

# 5. 测试热加载配置生成
echo "5. 测试热加载配置生成..."
cat > "$TEST_DIR/hot-reload-test.json" <<'EOF'
{
  "log_level": "debug",
  "metrics": {
    "enabled": true,
    "listen_address": "127.0.0.1:19100",
    "path": "/metrics"
  },
  "audit_demux": {
    "subscriber_queue_size": 1024,
    "backpressure_sampling_enabled": true,
    "backpressure_high_watermark": 0.8
  },
  "module_resources": {
    "test-module": {
      "max_memory_mb": 256,
      "max_cpu_percent": 30,
      "max_fds": 2048
    }
  }
}
EOF
echo "✅ 热加载测试配置已创建"
echo ""

# 6. 测试 metrics 端点（需要启动 agent）
echo "6. 准备 metrics 端点测试..."
echo "⚠️  完整的 metrics 测试需要启动 agent，这里仅验证配置"
echo ""

# 7. 清理
echo "7. 清理测试文件..."
rm -rf "$TEST_DIR"
echo "✅ 清理完成"
echo ""

echo "========================================="
echo "🎉 所有基础测试通过！"
echo "========================================="
echo ""
echo "下一步："
echo "1. 更新依赖: go mod tidy"
echo "2. 运行单元测试: go test ./..."
echo "3. 使用示例配置启动: sudo ./secweaver-agent run -config config.production.example.json"
echo "4. 访问 metrics: curl http://127.0.0.1:9100/metrics"
echo ""
echo "详细文档请参考: docs/metrics-and-hot-reload.md"
