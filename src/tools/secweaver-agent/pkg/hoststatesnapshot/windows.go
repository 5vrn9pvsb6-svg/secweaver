package hoststatesnapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"secweaver-agent/internal/agentactivity"
)

const windowsServiceScript = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $rows=@(); Get-CimInstance Win32_Service | ForEach-Object { $rows += [pscustomobject]@{ key=('service:'+([string]$_.Name)); entity_type='service'; service_name=[string]$_.Name; display_name=[string]$_.DisplayName; state=[string]$_.State; start_mode=[string]$_.StartMode; path_name=[string]$_.PathName; start_name=[string]$_.StartName; process_id=[string]$_.ProcessId } }; if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) { Get-ScheduledTask | ForEach-Object { $task=$_; $actions=@($task.Actions | ForEach-Object { (([string]$_.Execute)+' '+([string]$_.Arguments)).Trim() }) -join '; '; $triggers=@($task.Triggers | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 3 }) -join '; '; $rows += [pscustomobject]@{ key=('task:'+([string]$task.TaskPath)+([string]$task.TaskName)); entity_type='scheduled_task'; task_name=[string]$task.TaskName; task_path=[string]$task.TaskPath; task_type='windows_task_scheduler'; task_state=[string]$task.State; author=[string]$task.Author; description=[string]$task.Description; actions=$actions; triggers=$triggers } } }; @($rows) | ConvertTo-Json -Compress -Depth 4`
const windowsSocketScriptV2 = `$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$processes=@{}
Get-CimInstance Win32_Process | ForEach-Object { $processes[[int]$_.ProcessId]=$_ }
$owners=@{}
Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object { $owners[[int]$_.Id]=[string]$_.UserName }
$rows=@()
Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
  $p=$processes[[int]$_.OwningProcess]
  $rows += [pscustomobject]@{key=('tcp|{0}|{1}|{2}' -f $_.LocalAddress,$_.LocalPort,$_.OwningProcess);entity_type='listening_socket';protocol='tcp';listen_address=[string]$_.LocalAddress;listen_port=[int]$_.LocalPort;socket_state='LISTEN';pid=[string]$_.OwningProcess;process=[string]$p.Name;exe=[string]$p.ExecutablePath;user=[string]$owners[[int]$_.OwningProcess]}
}
Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
  $p=$processes[[int]$_.OwningProcess]
  $rows += [pscustomobject]@{key=('udp|{0}|{1}|{2}' -f $_.LocalAddress,$_.LocalPort,$_.OwningProcess);entity_type='listening_socket';protocol='udp';listen_address=[string]$_.LocalAddress;listen_port=[int]$_.LocalPort;socket_state='UNCONNECTED';pid=[string]$_.OwningProcess;process=[string]$p.Name;exe=[string]$p.ExecutablePath;user=[string]$owners[[int]$_.OwningProcess]}
}
@($rows) | ConvertTo-Json -Compress -Depth 4`

const windowsIdentityScriptV2 = `$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$rows=@()
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
  Get-LocalUser | ForEach-Object { $rows += [pscustomobject]@{key=('account:'+([string]$_.Name));entity_type='identity_account';user=[string]$_.Name;sid=[string]$_.SID;enabled=[bool]$_.Enabled;description=[string]$_.Description;last_logon=if ($_.LastLogon) {$_.LastLogon.ToUniversalTime().ToString('o')} else {''};password_expires=if ($_.PasswordExpires) {$_.PasswordExpires.ToUniversalTime().ToString('o')} else {''};password_required=[bool]$_.PasswordRequired;user_may_change_password=[bool]$_.UserMayChangePassword} }
} else {
  Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object { $rows += [pscustomobject]@{key=('account:'+([string]$_.Name));entity_type='identity_account';user=[string]$_.Name;sid=[string]$_.SID;enabled=(-not [bool]$_.Disabled);description=[string]$_.Description;password_expires=[bool]$_.PasswordExpires;password_required=[bool]$_.PasswordRequired} }
}
$sessions=@{}
Get-CimInstance Win32_LogonSession | Where-Object { $_.LogonType -in 2,3,10,11 } | ForEach-Object { $sessions[[string]$_.LogonId]=$_ }
Get-CimInstance Win32_LoggedOnUser | ForEach-Object {
  $session=$sessions[[string]$_.Dependent.LogonId]
  if ($session) {
    $account=$_.Antecedent
    $rows += [pscustomobject]@{key=('session:'+([string]$session.LogonId)+':'+([string]$account.Domain)+':'+([string]$account.Name));entity_type='login_session';user=[string]$account.Name;domain=[string]$account.Domain;session_id=[string]$session.LogonId;logon_type=[int]$session.LogonType;login_time=if ($session.StartTime) {$session.StartTime.ToUniversalTime().ToString('o')} else {''}}
  }
}
@($rows) | ConvertTo-Json -Compress -Depth 4`

const windowsKernelScriptV2 = `$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$rows=@()
Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object { $rows += [pscustomobject]@{key=('module:'+([string]$_.Name));entity_type='kernel_module';module_name=[string]$_.Name;display_name=[string]$_.DisplayName;module_state=[string]$_.State;start_mode=[string]$_.StartMode;path_name=[string]$_.PathName;service_type=[string]$_.ServiceType} }
$os=Get-CimInstance Win32_OperatingSystem
$rows += [pscustomobject]@{key='kernel:summary';entity_type='kernel_context';kernel_caption=[string]$os.Caption;kernel_version=[string]$os.Version;build_number=[string]$os.BuildNumber;system_directory=[string]$os.SystemDirectory;last_boot_time=if ($os.LastBootUpTime) {$os.LastBootUpTime.ToUniversalTime().ToString('o')} else {''}}
$services=@{}
Get-CimInstance Win32_Service | ForEach-Object { $services[[string]$_.Name]=$_ }
@('docker','containerd','vmcompute','hns') | ForEach-Object { $svc=$services[$_]; if ($svc) { $rows += [pscustomobject]@{key=('runtime:'+([string]$svc.Name));entity_type='container_context';container_runtime=[string]$svc.Name;runtime_state=[string]$svc.State;start_mode=[string]$svc.StartMode;path_name=[string]$svc.PathName;process_id=[string]$svc.ProcessId} } }
@($rows) | ConvertTo-Json -Compress -Depth 4`

func init() {
	// Register all scripts before any module starts so the independent unified
	// Event Log child can recognize historical and concurrent collector events.
	for _, script := range []string{windowsSocketScriptV2, windowsIdentityScriptV2, windowsServiceScript, windowsKernelScriptV2} {
		agentactivity.RegisterPowerShellScript(script)
	}
}

func collectWindowsSockets(ctx context.Context, _ time.Time) ([]entity, error) {
	return runWindowsEntityScript(ctx, windowsSocketScriptV2, "host_socket")
}

func collectWindowsIdentity(ctx context.Context, _ time.Time) ([]entity, error) {
	return runWindowsEntityScript(ctx, windowsIdentityScriptV2, "host_identity")
}

func collectWindowsServices(ctx context.Context, _ time.Time) ([]entity, error) {
	return runWindowsEntityScript(ctx, windowsServiceScript, "host_service")
}

func collectWindowsKernel(ctx context.Context, _ time.Time) ([]entity, error) {
	return runWindowsEntityScript(ctx, windowsKernelScriptV2, "host_kernel_context")
}

func runWindowsEntityScript(ctx context.Context, script, assetType string) ([]entity, error) {
	markedScript := agentactivity.MarkPowerShellScript(script)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", markedScript)
	body, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("PowerShell host-state query failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}
	return decodeWindowsEntities(body, assetType)
}

func decodeWindowsEntities(body []byte, assetType string) ([]entity, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var rows []map[string]any
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, fmt.Errorf("decode PowerShell host-state array: %w", err)
		}
	} else {
		var row map[string]any
		if err := json.Unmarshal(trimmed, &row); err != nil {
			return nil, fmt.Errorf("decode PowerShell host-state object: %w", err)
		}
		rows = append(rows, row)
	}
	entities := make([]entity, 0, len(rows))
	for _, row := range rows {
		key := strings.TrimSpace(fmt.Sprint(row["key"]))
		entityType := strings.TrimSpace(fmt.Sprint(row["entity_type"]))
		delete(row, "key")
		delete(row, "entity_type")
		if key == "" || entityType == "" {
			continue
		}
		for field, value := range row {
			if value == nil || value == "" {
				delete(row, field)
			}
		}
		entities = append(entities, entity{Key: key, EntityType: entityType, AssetType: assetType, Fields: row})
	}
	return entities, nil
}
