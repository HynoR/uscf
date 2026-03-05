package cmd

import (
	"testing"

	"github.com/HynoR/uscf/config"
)

func TestDecideStartupActionMatrix(t *testing.T) {
	baseCfg := config.Config{
		ID:          "device-id",
		AccessToken: "token",
	}

	t.Run("valid free without params uses existing", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = accountModeFree

		decision, err := decideStartupAction(true, cfg, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupUseExisting {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
		if decision.EffectiveMode != accountModeFree {
			t.Fatalf("unexpected mode: %s", decision.EffectiveMode)
		}
	})

	t.Run("valid free with license registers premium", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = accountModeFree

		decision, err := decideStartupAction(true, cfg, "L1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupRegisterPremium {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
		if decision.EffectiveMode != accountModePremium {
			t.Fatalf("unexpected mode: %s", decision.EffectiveMode)
		}
	})

	t.Run("valid free with jwt registers team", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = accountModeFree

		decision, err := decideStartupAction(true, cfg, "", "J1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupRegisterTeam {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
		if decision.EffectiveMode != accountModeTeam {
			t.Fatalf("unexpected mode: %s", decision.EffectiveMode)
		}
	})

	t.Run("valid premium ignores license", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = accountModePremium

		decision, err := decideStartupAction(true, cfg, "L1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupUseExisting {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
		if !decision.IgnoredLicense {
			t.Fatalf("expected ignored license")
		}
	})

	t.Run("valid premium ignores jwt", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = accountModePremium

		decision, err := decideStartupAction(true, cfg, "", "J1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupUseExisting {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
		if !decision.IgnoredJWT {
			t.Fatalf("expected ignored jwt")
		}
	})

	t.Run("valid team ignores license", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = accountModeTeam

		decision, err := decideStartupAction(true, cfg, "L1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupUseExisting {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
		if !decision.IgnoredLicense {
			t.Fatalf("expected ignored license")
		}
	})

	t.Run("invalid config with license registers premium", func(t *testing.T) {
		cfg := config.Config{
			ID:          "device-id",
			AccessToken: "",
			AccountMode: accountModeFree,
		}

		decision, err := decideStartupAction(true, cfg, "L1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupRegisterPremium {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
	})

	t.Run("invalid config with jwt registers team", func(t *testing.T) {
		cfg := config.Config{
			ID:          "",
			AccessToken: "token",
			AccountMode: accountModeTeam,
		}

		decision, err := decideStartupAction(true, cfg, "", "J1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupRegisterTeam {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
	})

	t.Run("invalid config without params registers free", func(t *testing.T) {
		cfg := config.Config{}

		decision, err := decideStartupAction(true, cfg, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != startupRegisterFree {
			t.Fatalf("unexpected action: %s", decision.Action)
		}
	})

	t.Run("missing mode infers team from t prefix", func(t *testing.T) {
		cfg := baseCfg
		cfg.ID = "t.device-id"

		decision, err := decideStartupAction(true, cfg, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.EffectiveMode != accountModeTeam {
			t.Fatalf("unexpected mode: %s", decision.EffectiveMode)
		}
		if !decision.ShouldPersistMode {
			t.Fatalf("expected inferred mode to be persisted")
		}
	})

	t.Run("missing mode infers premium when license matches", func(t *testing.T) {
		cfg := baseCfg
		cfg.License = "L1"

		decision, err := decideStartupAction(true, cfg, "L1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.EffectiveMode != accountModePremium {
			t.Fatalf("unexpected mode: %s", decision.EffectiveMode)
		}
		if !decision.ShouldPersistMode {
			t.Fatalf("expected inferred mode to be persisted")
		}
	})

	t.Run("invalid mode falls back to free", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = "weird"

		decision, err := decideStartupAction(true, cfg, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.EffectiveMode != accountModeFree {
			t.Fatalf("unexpected mode: %s", decision.EffectiveMode)
		}
		if !decision.ModeWasInvalid {
			t.Fatalf("expected invalid mode flag")
		}
		if !decision.ShouldPersistMode {
			t.Fatalf("expected normalized mode to be persisted")
		}
	})

	t.Run("license and jwt together returns error", func(t *testing.T) {
		cfg := baseCfg
		cfg.AccountMode = accountModeFree

		if _, err := decideStartupAction(true, cfg, "L1", "J1"); err == nil {
			t.Fatalf("expected error")
		}
	})
}
