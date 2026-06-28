package pluginmgr

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/msrsiddik/apicorex-identity/internal/migrator"
)

// CoreRegistry implements PluginRegistry by pulling a plugin's manifest from
// Core's HTTP control plane: GET {coreURL}/_core/plugins/{name}/manifest.
type CoreRegistry struct {
	coreURL string
	client  *http.Client
}

// NewCoreRegistry returns a registry client that pulls plugin manifests from
// Core at coreURL.
func NewCoreRegistry(coreURL string) *CoreRegistry {
	return &CoreRegistry{coreURL: coreURL, client: &http.Client{Timeout: 10 * time.Second}}
}

// manifestJSON mirrors the relevant fields of the manifest Core stores.
type manifestJSON struct {
	Migrations []struct {
		Version string `json:"version"`
		Name    string `json:"name"`
		UpSQL   string `json:"up_sql"`
		DownSQL string `json:"down_sql"`
	} `json:"migrations"`
}

func (r *CoreRegistry) GetManifest(pluginName string) (PluginManifest, bool) {
	resp, err := r.client.Get(r.coreURL + "/_core/plugins/" + pluginName + "/manifest")
	if err != nil {
		return PluginManifest{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PluginManifest{}, false
	}
	var mj manifestJSON
	if err := json.NewDecoder(resp.Body).Decode(&mj); err != nil {
		return PluginManifest{}, false
	}
	migrations := make([]migrator.Migration, 0, len(mj.Migrations))
	for _, m := range mj.Migrations {
		migrations = append(migrations, migrator.Migration{
			Version: m.Version, Name: m.Name, UpSQL: m.UpSQL, DownSQL: m.DownSQL,
		})
	}
	return PluginManifest{Migrations: migrations}, true
}
