package main

import "testing"

func TestLearningDiagnosticsDoNotCertifyIncompleteWindowsSetup(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := agentConfig{EnterpriseID: "TEST000000000000"}
		cfg.License.StatePath = t.TempDir() + "/missing.json"
		args := []string{}
		if enabled {
			args = append(args, "-behavior-learning")
		}
		modules := []runtimeModule{{Spec: moduleSpec{Name: "windows-eventlog-risk-json"}, Config: moduleConfig{Args: args}}}
		checks := map[string]doctorLevel{}
		doctorCheckWindowsLearning(cfg, modules, false, func(level doctorLevel, component, _, _ string) { checks[component] = level })
		if checks["authorization"] != doctorWarn {
			t.Fatal("disabled authorization hidden")
		}
		if enabled {
			if checks["learning/identity"] != doctorWarn || checks["learning/capability"] != doctorWarn {
				t.Fatal("incomplete setup certified")
			}
		} else if checks["learning/config"] != doctorWarn {
			t.Fatal("legacy learning state hidden")
		}
	}
}
