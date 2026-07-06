package helpers

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

func TestGetStringMapFilteredPreservesConfigKeysWithEmptyAPIValues(t *testing.T) {
	t.Parallel()

	apiResult := map[string]gjson.Result{
		"RequiresRoutableAddress": gjson.Parse(`""`),
		"InjectedByISE":           gjson.Parse(`""`),
	}
	configMap := types.MapValueMust(types.StringType, map[string]attr.Value{
		"RequiresRoutableAddress": types.StringValue(""),
	})

	m := GetStringMapFiltered(apiResult, configMap)
	elements := m.Elements()
	if len(elements) != 1 {
		t.Fatalf("expected 1 config key preserved, got %d", len(elements))
	}
	if v, ok := elements["RequiresRoutableAddress"]; !ok {
		t.Fatalf("expected RequiresRoutableAddress key preserved, got %#v", elements)
	} else if sv, ok := v.(types.String); !ok || sv.ValueString() != "" {
		t.Fatalf("expected empty string preserved for declared config key, got %#v", v)
	}
}

func TestGetStringMapFilteredImportUsesAllAPIKeys(t *testing.T) {
	t.Parallel()

	apiResult := map[string]gjson.Result{
		"RequiresRoutableAddress": gjson.Parse(`""`),
	}
	m := GetStringMapFiltered(apiResult, types.MapNull(types.StringType))
	elements := m.Elements()
	if len(elements) != 1 {
		t.Fatalf("expected all API keys when config is null, got %d", len(elements))
	}
}
