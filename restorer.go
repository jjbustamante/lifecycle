package lifecycle

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/buildpacks/lifecycle/api"
	"github.com/buildpacks/lifecycle/buildpack"
	"github.com/buildpacks/lifecycle/internal/layer"
	"github.com/buildpacks/lifecycle/launch"
	"github.com/buildpacks/lifecycle/layers"
	"github.com/buildpacks/lifecycle/platform"
)

type Restorer struct {
	LayersDir string
	Logger    Logger

	Buildpacks            []buildpack.GroupBuildpack
	LayerMetadataRestorer layer.MetadataRestorer  // Platform API >= 0.7
	LayersMetadata        platform.LayersMetadata // Platform API >= 0.7
	Platform              Platform
}

// Restore restores metadata for launch and cache layers into the layers directory and attempts to restore layer data for cache=true layers, removing the layer when unsuccessful.
// If a usable cache is not provided, Restore will not restore any cache=true layer metadata.
func (r *Restorer) Restore(cache Cache) error {
	cacheMeta, err := retrieveCacheMetadata(cache, r.Logger)
	if err != nil {
		return err
	}

	useShaFiles := !r.restoresLayerMetadata()
	layerSHAStore := layer.NewSHAStore(useShaFiles)
	if r.restoresLayerMetadata() {
		if err := r.LayerMetadataRestorer.Restore(r.Buildpacks, r.LayersMetadata, cacheMeta, layerSHAStore); err != nil {
			return err
		}
	}

	var g errgroup.Group
	for _, bp := range r.Buildpacks {
		cachedLayers := cacheMeta.MetadataForBuildpack(bp.ID).Layers

		var cachedFn func(buildpack.Layer) bool
		if api.MustParse(bp.API).AtLeast("0.6") {
			// On Buildpack API 0.6+, the <layer>.toml file never contains layer types information.
			// The cache metadata is the only way to identify cache=true layers.
			cachedFn = func(l buildpack.Layer) bool {
				bpLayer, ok := cachedLayers[filepath.Base(l.Path())]
				return ok && bpLayer.Cache
			}
		} else {
			// On Buildpack API < 0.6, the <layer>.toml file contains layer types information.
			// Prefer <layer>.toml file to cache metadata in case the cache was cleared between builds and
			// the analyzer that wrote the files is on a previous version of the lifecycle, that doesn't cross-reference the cache metadata when writing the files.
			// This allows the restorer to cleanup <layer>.toml files for layers that are not actually in the cache.
			cachedFn = buildpack.MadeCached
		}

		buildpackDir, err := buildpack.ReadLayersDir(r.LayersDir, bp, r.Logger)
		if err != nil {
			return errors.Wrapf(err, "reading buildpack layer directory")
		}
		foundLayers := buildpackDir.FindLayers(cachedFn)

		for _, bpLayer := range foundLayers {
			cachedLayer, exists := cachedLayers[bpLayer.Name()]
			if !exists {
				r.Logger.Infof("Removing %q, not in cache", bpLayer.Identifier())
				if err := bpLayer.Remove(); err != nil {
					return errors.Wrapf(err, "removing layer")
				}
				continue
			}

			layerSha, err := layerSHAStore.Get(bp.ID, bpLayer)
			if err != nil {
				return err
			}

			if layerSha != cachedLayer.SHA {
				r.Logger.Infof("Removing %q, wrong sha", bpLayer.Identifier())
				r.Logger.Debugf("Layer sha: %q, cache sha: %q", layerSha, cachedLayer.SHA)
				if err := bpLayer.Remove(); err != nil {
					return errors.Wrapf(err, "removing layer")
				}
			} else {
				r.Logger.Infof("Restoring data for %q from cache", bpLayer.Identifier())
				g.Go(func() error {
					return r.restoreCacheLayer(cache, cachedLayer.SHA)
				})
			}
		}
	}

	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "restoring data")
	}

	if api.MustParse(r.Platform.API()).AtLeast("0.8") {
		return r.restoreSBOM()
	}

	return nil
}

func (r *Restorer) restoresLayerMetadata() bool {
	return api.MustParse(r.Platform.API()).AtLeast("0.7")
}

func (r *Restorer) restoreCacheLayer(cache Cache, sha string) error {
	// Sanity check to prevent panic.
	if cache == nil {
		return errors.New("restoring layer: cache not provided")
	}
	r.Logger.Debugf("Retrieving data for %q", sha)
	rc, err := cache.RetrieveLayer(sha)
	if err != nil {
		return err
	}
	defer rc.Close()

	return layers.Extract(rc, "")
}

func (r *Restorer) restoreSBOM() error {
	var (
		cacheDir  = filepath.Join(r.LayersDir, "sbom", "cache")
		launchDir = filepath.Join(r.LayersDir, "sbom", "launch")
	)

	defer os.RemoveAll(filepath.Join(r.LayersDir, "sbom"))

	err := filepath.Walk(cacheDir, r.restoreSBOMFunc("cache"))
	if err != nil {
		return err
	}

	err = filepath.Walk(launchDir, r.restoreSBOMFunc("launch"))
	if err != nil {
		return err
	}

	return nil
}

func (r *Restorer) restoreSBOMFunc(bomType string) func(path string, info fs.FileInfo, err error) error {
	var bomRegex *regexp.Regexp

	if runtime.GOOS == "windows" {
		bomRegex = regexp.MustCompile(fmt.Sprintf(`%s\\(.+)\\(.+)\\(sbom.+json)`, bomType))
	} else {
		bomRegex = regexp.MustCompile(fmt.Sprintf(`%s/(.+)/(.+)/(sbom.+json)`, bomType))
	}

	return func(path string, info fs.FileInfo, err error) error {
		if info == nil || !info.Mode().IsRegular() {
			return nil
		}

		matches := bomRegex.FindStringSubmatch(path)
		if len(matches) != 4 {
			return nil
		}

		var (
			buildpackID = matches[1]
			layerName   = matches[2]
			fileName    = matches[3]
			dest        = filepath.Join(r.LayersDir, buildpackID, fmt.Sprintf("%s.%s", layerName, fileName))
		)

		if !r.buildpackDetected(buildpackID) {
			return nil
		}

		return Copy(path, dest)
	}
}

func (r *Restorer) buildpackDetected(id string) bool {
	for _, bp := range r.Buildpacks {
		if launch.EscapeID(bp.ID) == id {
			return true
		}
	}

	return false
}
