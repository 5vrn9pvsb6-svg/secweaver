const ASSET_TYPES = [
  "waf_alert",
  "web_access_log",
  "host_exec",
  "host_connect",
  "host_file_op",
  "host_persistence",
  "host_process",
  "host_socket",
  "host_identity",
  "host_service",
  "host_kernel_context",
  "windows_event_log",
  "linux_syslog",
  "syslog_risk_alert",
  "ssh_auth",
  "firewall_log",
  "dns_log",
  "network_traffic_audit",
  "ids_alert",
  "edr_event",
  "asset_inventory",
  "vuln_scan",
  "db_audit",
  "app_api_log",
];

const ASSET_DOMAINS = ["D1", "D2", "D3", "D4", "D5", "D6", "D7"];
const ASSET_STATUSES = ["draft", "discovery", "active", "disabled"];
const ASSET_SENSITIVITIES = ["public", "internal", "confidential", "restricted"];
const TEXT_PARSERS = ["", "syslog_auth", "nginx_combined", "json_lines", "json_lines2", "raw_only"];
const CONNECTOR_STATUSES = ["draft", "active", "disabled"];
const CONNECTOR_TYPES = [
  "sls", "sls_proxy", "ssh_file", "database_ro", "http_api", "es", "local_file", "agent_stream",
  "aws_cloudwatch", "aws_s3_logs", "azure_monitor", "gcp_logging", "tencent_cls",
  "huawei_lts", "splunk", "clickhouse", "hive", "mongodb", "redis",
  "object_storage", "syslog_ingest", "external_generic",
];
const NETWORK_TYPES = ["dmz", "production", "office", "management", "lab", "cloud_vpc", "external", "other"];
const NETWORK_TRUST_LEVELS = ["external", "dmz", "internal", "restricted", "management"];
const NETWORK_STATUSES = ["draft", "active", "retired"];
const BUNDLE_STATUSES = ["draft", "active", "disabled"];
const INVESTIGATION_SCENARIOS = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"];

const CREDENTIAL_TYPE_TEMPLATES = {
  aliyun_ram: `type: aliyun_ram
access_key_id: "LTAI_REPLACE_ME"
access_key_secret: "REPLACE_ME"
# security_token: ""  # STS 临时凭证时填写
`,
  aws: `type: aws
access_key_id: "AKIA_REPLACE_ME"
secret_access_key: "REPLACE_ME"
region: "us-east-1"
# session_token: ""  # STS 临时凭证时填写
`,
  azure_monitor: `type: azure_monitor
tenant_id: "REPLACE_ME"
client_id: "REPLACE_ME"
client_secret: "REPLACE_ME"
workspace_id: "REPLACE_ME"
# access_token: ""  # 已有短期 token 时可直接填写
`,
  gcp_service_account: `type: gcp_service_account
project_id: "REPLACE_ME"
client_email: "service-account@example.iam.gserviceaccount.com"
private_key: "REPLACE_ME_WITH_LOCAL_SOPS_ENCRYPTED_PRIVATE_KEY"
token_uri: "https://oauth2.googleapis.com/token"
# access_token: ""  # 已有短期 token 时可直接填写
`,
  tencent_cam: `type: tencent_cam
secret_id: "REPLACE_ME"
secret_key: "REPLACE_ME"
region: "ap-guangzhou"
`,
  huawei_iam: `type: huawei_iam
access_key: "REPLACE_ME"
secret_key: "REPLACE_ME"
project_id: "REPLACE_ME"
region: "cn-north-4"
# token: ""  # 已有 IAM token 时可直接填写
`,
  ssh: `type: ssh
username: readonly
auth_method: key   # 或 password
private_key: "REPLACE_ME_WITH_LOCAL_SOPS_ENCRYPTED_PRIVATE_KEY"
password: ""
`,
  mysql: `type: mysql
username: ai_readonly
password: "REPLACE_ME"
`,
  postgresql: `type: postgresql
username: ai_readonly
password: "REPLACE_ME"
`,
  postgres: `type: postgres
username: ai_readonly
password: "REPLACE_ME"
`,
  oracle: `type: oracle
username: ai_readonly
password: "REPLACE_ME"
# dsn: "dbhost:1521/service"
`,
  plsql: `type: plsql
username: ai_readonly
password: "REPLACE_ME"
# dsn: "dbhost:1521/service"
`,
  sqlserver: `type: sqlserver
username: ai_readonly
password: "REPLACE_ME"
# driver: "ODBC Driver 18 for SQL Server"
`,
  mssql: `type: mssql
username: ai_readonly
password: "REPLACE_ME"
`,
  sqlite: `type: sqlite
# SQLite 通常无需用户名密码；凭证文件仅用于统一引用。
`,
  mongodb: `type: mongodb
username: readonly
password: "REPLACE_ME"
# auth_source: "admin"
`,
  redis: `type: redis
password: "REPLACE_ME"
# username: ""
`,
  clickhouse: `type: clickhouse
username: readonly
password: "REPLACE_ME"
`,
  hive: `type: hive
username: readonly
password: "REPLACE_ME"
# kerberos_principal: ""
# keytab: ""
`,
  http_api: `type: http_api
auth_method: bearer
token: "REPLACE_ME"
`,
  oauth2_client_credentials: `type: oauth2_client_credentials
token_url: "https://example.com/oauth/token"
client_id: "REPLACE_ME"
client_secret: "REPLACE_ME"
scope: ""
`,
  api_key: `type: api_key
key_name: "Authorization"
key_value: "Bearer REPLACE_ME"
placement: "header"
`,
  es: `type: es
username: es_readonly
password: "REPLACE_ME"
# 或 api_key: "id:secret"
`,
  splunk: `type: splunk
auth_method: bearer
token: "REPLACE_ME"
`,
  syslog_token: `type: syslog_token
token: "REPLACE_ME"
`,
  agent_stream: `type: agent_stream
token: "REPLACE_ME"
`,
  object_storage: `type: object_storage
access_key_id: "REPLACE_ME"
access_key_secret: "REPLACE_ME"
endpoint: "https://s3.example.com"
region: "us-east-1"
`,
  virustotal: `type: virustotal
token: "REPLACE_ME"
`,
  datadog: `type: datadog
api_key: "REPLACE_ME"
app_key: "REPLACE_ME"
site: "datadoghq.com"
`,
  custom: `type: custom
# 请按外部 Connector 或执行器要求手动编辑 YAML 字段。
`,
};

const CREDENTIAL_TYPES = Object.keys(CREDENTIAL_TYPE_TEMPLATES);
const CREDENTIAL_BUILTIN_COMMON_TYPES = [
  "aws",
  "azure_monitor",
  "gcp_service_account",
  "tencent_cam",
  "huawei_iam",
  "splunk",
  "mysql",
  "postgresql",
  "oracle",
  "sqlserver",
  "sqlite",
  "mongodb",
  "redis",
  "clickhouse",
  "hive",
];
const CREDENTIAL_BUILTIN_GENERIC_TYPES = [
  "aliyun_ram",
  "ssh",
  "postgres",
  "plsql",
  "mssql",
  "http_api",
  "oauth2_client_credentials",
  "api_key",
  "es",
  "syslog_token",
  "agent_stream",
  "object_storage",
  "virustotal",
  "datadog",
  "custom",
];
const CREDENTIAL_TYPE_ALIASES = {
  sls: "aliyun_ram",
  sls_proxy: "aliyun_ram",
  aliyun_sls: "aliyun_ram",
  aws_cloudwatch: "aws",
  aws_s3_logs: "aws",
  aws_s3: "aws",
  azure: "azure_monitor",
  azure_log_analytics: "azure_monitor",
  gcp: "gcp_service_account",
  gcp_logging: "gcp_service_account",
  tencent: "tencent_cam",
  tencent_cls: "tencent_cam",
  huawei: "huawei_iam",
  huawei_lts: "huawei_iam",
  database: "mysql",
  database_ro: "mysql",
  db: "mysql",
  ora: "oracle",
  oracle_db: "oracle",
  mssql_server: "sqlserver",
  sql_server: "sqlserver",
  mongo: "mongodb",
  elasticsearch: "es",
  splunk_hec: "splunk",
  syslog: "syslog_token",
  syslog_ingest: "syslog_token",
  agent: "agent_stream",
  http: "http_api",
  waf: "http_api",
  object_storage_s3: "object_storage",
  "object-storage": "object_storage",
  external_generic: "http_api",
};

const HOST_TYPES = ["server", "network_device", "endpoint", "gateway"];
const HOST_OSES = ["linux", "windows", "macos", "network_os", "other"];
const ENVIRONMENTS = ["production", "staging", "development"];
const HOST_STATUSES = ["draft", "active", "retired"];

const MODULE_PAGES = {
  asset: {
    label: "数据资产",
    kicker: "Data Asset",
    description: "管理安全数据源资产、字段、连接器和查询模板。",
    registryKey: "assets",
    detailKind: "asset",
    idField: "asset_id",
    editable: true,
    deletable: true,
    canCreate: true,
    newButtonText: "新建资产",
    newTemplate: () => ({
      asset_id: `asset-new-${Date.now()}`,
      name: "新数据源资产",
      asset_type: "host_exec",
      domain: "D2",
      status: "draft",
      environment: "development",
      connector_id: "",
      owner_team: "security-ops",
      sensitivity: "internal",
      schema: { fields: ["timestamp", "host"], time_field: "timestamp", retention_days: 30 },
      coverage: { hosts: [] },
      tags: [],
    }),
  },
  connector: {
    label: "Connector",
    kicker: "Connector",
    description: "管理数据源连接器配置与接入方式。",
    registryKey: "connectors",
    detailKind: "connector",
    idField: "connector_id",
    editable: true,
    deletable: true,
    canCreate: true,
    newButtonText: "新建 Connector",
    newTemplate: () => ({
      connector_id: `conn-new-${Date.now()}`,
      name: "新 Connector",
      connector_type: "local_file",
      status: "draft",
      environment: "development",
      credentials_ref: "",
      config: { base_path: "dataasset/samples/local-logs" },
      constraints: {},
      tags: [],
    }),
  },
  credential: {
    label: "Credentials",
    kicker: "Credentials",
    description: "管理 examples/secrets 下的凭证 YAML 文件；加密文件仅编辑密文，不在 UI 解密。",
    registryKey: "credentials",
    detailKind: "credential",
    idField: "credential_id",
    editable: true,
    deletable: true,
    canCreate: true,
    newButtonText: "新建 Credentials",
    newTemplate: () => ({
      credential_id: "",
      credential_type: "",
      status: "active",
      content: "",
    }),
  },
  host: {
    label: "主机",
    kicker: "Host",
    description: "管理主机身份、网络位置、角色和标签。",
    registryKey: "hosts",
    detailKind: "host",
    idField: "host_id",
    editable: true,
    deletable: true,
    canCreate: true,
    newButtonText: "新建主机",
    newTemplate: () => ({
      host_id: `host-lab-demo-${Date.now()}`,
      name: "Lab Host",
      hostname: "lab-host-01",
      host_type: "server",
      host_os: "linux",
      host_ip: "10.0.1.10",
      network_id: "net-prod-web",
      exposure: {
        internet_exposed: false,
        internet_ip: "",
        exposed_ports: []
      },
      aliases: [],
      roles: [
        "web"
      ],
      environment: "development",
      status: "draft",
      description: "Synthetic lab host for demos. Use RFC 5737 or private lab IPs only.",
      tags: [
        "demo",
        "lab"
      ],
    }),
  },
  network: {
    label: "网络",
    kicker: "Network",
    description: "管理网段、逻辑区域、网络用途和信任等级。",
    registryKey: "networks",
    detailKind: "network",
    idField: "network_id",
    editable: true,
    deletable: true,
    canCreate: true,
    newButtonText: "新建网络",
    newTemplate: () => ({
      network_id: `net-new-${Date.now()}`,
      name: "新网络",
      network_type: "production",
      cidr: "10.0.0.0/24",
      zone: "production_network",
      trust_level: "internal",
      environment: "production",
      status: "draft",
      tags: [],
    }),
  },
  bundle: {
    label: "Bundle",
    kicker: "Bundle",
    description: "管理调查场景所需的数据资产包。",
    registryKey: "bundles",
    detailKind: "bundle",
    idField: "bundle_id",
    editable: true,
    deletable: true,
    canCreate: true,
    newButtonText: "新建 Bundle",
    newTemplate: () => ({
      bundle_id: `bundle-new-${Date.now()}`,
      name: "新 Bundle",
      status: "draft",
      environment: "development",
      asset_ids: [],
      description: "",
      tags: [],
    }),
  },
  correlation: {
    label: "Correlation Matrix",
    kicker: "Correlation",
    description: "编辑跨源 Join 合同、时间窗与关联规则。",
    registryKey: "correlations",
    detailKind: "correlation",
    editable: true,
    deletable: false,
    canCreate: false,
    singleton: true,
    singletonId: "correlation-matrix",
  },
  scenario: {
    label: "Scenario Pattern",
    kicker: "Scenario",
    description: "编辑调查场景编排、推荐 Join 链和默认资产包。",
    registryKey: "scenarios",
    detailKind: "scenario",
    editable: true,
    deletable: false,
    canCreate: false,
    singleton: true,
    singletonId: "anchor-patterns",
  },
};
