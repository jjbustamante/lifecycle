package main

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/buildpacks/imgutil"
	"github.com/buildpacks/imgutil/local"
	"github.com/buildpacks/imgutil/remote"
	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"

	"github.com/buildpacks/lifecycle"
	"github.com/buildpacks/lifecycle/api"
	"github.com/buildpacks/lifecycle/auth"
	"github.com/buildpacks/lifecycle/buildpack"
	"github.com/buildpacks/lifecycle/cmd"
	"github.com/buildpacks/lifecycle/platform"
	"github.com/buildpacks/lifecycle/priv"
)

type analyzeCmd struct {
	//flags: inputs
	analyzeArgs
	uid, gid int

	//flags: paths to write data
	analyzedPath string
}

type analyzeArgs struct {
	imageName   string
	layersDir   string
	orderPath   string //nolint - Platform API >= 0.7
	runImageRef string //nolint - Platform API >= 0.7
	stackPath   string //nolint - Platform API >= 0.7
	useDaemon   bool

	platform06     analyzeArgsPlatform06
	additionalTags cmd.StringSlice        //nolint Platform API >= 0.7
	docker         client.CommonAPIClient // construct if necessary before dropping privileges
	keychain       authn.Keychain
	platform       cmd.Platform
}

type analyzeArgsPlatform06 struct {
	cacheDir      string
	cacheImageTag string
	groupPath     string
	skipLayers    bool
	cache         lifecycle.Cache
	group         buildpack.Group
}

func (a *analyzeCmd) DefineFlags() {
	cmd.FlagAnalyzedPath(&a.analyzedPath)
	cmd.FlagLayersDir(&a.layersDir)
	if a.platformAPIVersionGreaterThan06() {
		cmd.FlagOrderPath(&a.orderPath)
		cmd.FlagPreviousImage(&a.imageName)
		cmd.FlagRunImage(&a.runImageRef)
		cmd.FlagStackPath(&a.stackPath)
		cmd.FlagTags(&a.additionalTags)
	} else {
		cmd.FlagCacheImage(&a.platform06.cacheImageTag)
		cmd.FlagCacheDir(&a.platform06.cacheDir)
		cmd.FlagGroupPath(&a.platform06.groupPath)
		cmd.FlagSkipLayers(&a.platform06.skipLayers)
	}
	cmd.FlagUseDaemon(&a.useDaemon)
	cmd.FlagUID(&a.uid)
	cmd.FlagGID(&a.gid)
}

func (a *analyzeCmd) Args(nargs int, args []string) error {
	if a.supportsImageArgument() {
		if nargs != 1 {
			return cmd.FailErrCode(fmt.Errorf("received %d arguments, but expected 1", nargs), cmd.CodeInvalidArgs, "parse arguments")
		}
		if args[0] == "" {
			return cmd.FailErrCode(errors.New("image argument is required"), cmd.CodeInvalidArgs, "parse arguments")
		}
		a.imageName = args[0]
	} else if nargs != 0 {
		return cmd.FailErrCode(errors.New("received unexpected arguments"), cmd.CodeInvalidArgs, "parse arguments")
	}

	if a.restoresLayerMetadata() {
		if a.platform06.cacheImageTag == "" && a.platform06.cacheDir == "" {
			cmd.DefaultLogger.Warn("Not restoring cached layer metadata, no cache flag specified.")
		}
	}

	if a.analyzedPath == cmd.PlaceholderAnalyzedPath {
		a.analyzedPath = cmd.DefaultAnalyzedPath(a.platform.API(), a.layersDir)
	}

	if a.platform06.groupPath == cmd.PlaceholderGroupPath {
		a.platform06.groupPath = cmd.DefaultGroupPath(a.platform.API(), a.layersDir)
	}

	if a.orderPath == cmd.PlaceholderOrderPath {
		a.orderPath = cmd.DefaultOrderPath(a.platform.API(), a.layersDir)
	}

	return nil
}

func (a *analyzeCmd) Privileges() error {
	var err error
	a.keychain, err = auth.DefaultKeychain(a.registryImages()...)
	if err != nil {
		return cmd.FailErr(err, "resolve keychain")
	}

	if a.useDaemon {
		var err error
		a.docker, err = priv.DockerClient()
		if err != nil {
			return cmd.FailErr(err, "initialize docker client")
		}
	}
	if err := priv.EnsureOwner(a.uid, a.gid, a.layersDir, a.platform06.cacheDir); err != nil {
		return cmd.FailErr(err, "chown volumes")
	}
	if err := priv.RunAs(a.uid, a.gid); err != nil {
		return cmd.FailErr(err, fmt.Sprintf("exec as user %d:%d", a.uid, a.gid))
	}
	return nil
}

func (a *analyzeCmd) Exec() error {
	var (
		group      buildpack.Group
		err        error
		cacheStore lifecycle.Cache
	)
	if a.restoresLayerMetadata() {
		group, err = lifecycle.ReadGroup(a.platform06.groupPath)
		if err != nil {
			return cmd.FailErr(err, "read buildpack group")
		}
		if err := verifyBuildpackApis(group); err != nil {
			return err
		}
		cacheStore, err = initCache(a.platform06.cacheImageTag, a.platform06.cacheDir, a.keychain)
		if err != nil {
			return cmd.FailErr(err, "initialize cache")
		}
		a.platform06.group = group
		a.platform06.cache = cacheStore
	}

	if a.orderPath != "" {
		_, err := lifecycle.ReadOrder(a.orderPath)
		if err != nil {
			return cmd.FailErr(err, "read buildpack order file")
		}
	}

	if err := a.validateStack(); err != nil {
		return cmd.FailErr(err, "validate stack")
	}

	analyzedMD, err := a.analyze()
	if err != nil {
		return err
	}

	if err := lifecycle.WriteTOML(a.analyzedPath, analyzedMD); err != nil {
		return errors.Wrap(err, "write analyzed.toml")
	}

	return nil
}

func (aa analyzeArgs) analyze() (platform.AnalyzedMetadata, error) {
	var (
		img imgutil.Image
		err error
	)
	if aa.imageName != "" {
		if aa.useDaemon {
			img, err = local.NewImage(
				aa.imageName,
				aa.docker,
				local.FromBaseImage(aa.imageName),
			)
		} else {
			img, err = remote.NewImage(
				aa.imageName,
				aa.keychain,
				remote.FromBaseImage(aa.imageName),
			)
		}
		if err != nil {
			return platform.AnalyzedMetadata{}, cmd.FailErr(err, "get previous image")
		}
	}

	analyzedMD, err := (&lifecycle.Analyzer{
		Buildpacks:            aa.platform06.group.Group,
		Cache:                 aa.platform06.cache,
		Logger:                cmd.DefaultLogger,
		Platform:              aa.platform,
		Image:                 img,
		LayerMetadataRestorer: lifecycle.NewLayerMetadataRestorer(cmd.DefaultLogger, aa.layersDir, aa.platform06.skipLayers),
	}).Analyze()
	if err != nil {
		return platform.AnalyzedMetadata{}, cmd.FailErrCode(err, aa.platform.CodeFor(cmd.AnalyzeError), "analyzer")
	}
	return analyzedMD, nil
}

func (a *analyzeCmd) validateStack() error {
	if !a.supportsStackValidation() {
		return nil
	}

	var stackMD platform.StackMetadata
	if _, err := toml.DecodeFile(a.stackPath, &stackMD); err != nil && !os.IsNotExist(err) {
		return cmd.FailErr(err, "get stack metadata")
	}

	buildStackID, err := a.resolveBuildStack(stackMD)
	if err != nil {
		return cmd.FailErr(err, "resolve stack")
	}

	runImage, err := a.resolveRunImage(stackMD)
	if err != nil {
		return cmd.FailErr(err, "resolve run image")
	}

	runStackID, err := runImage.Label(platform.StackIDLabel)
	if err != nil {
		return errors.Wrap(err, "get run image label")
	}
	if runStackID == "" {
		return errors.New("get run image label: io.buildpacks.stack.id")
	}

	if buildStackID != runStackID {
		return errors.New(fmt.Sprintf("incompatible stack: '%s' is not compatible with '%s'", runStackID, buildStackID))
	}
	return nil
}

func (a *analyzeCmd) resolveBuildStack(stackMD platform.StackMetadata) (string, error) {
	buildStackID := os.Getenv(cmd.EnvStackID)
	if buildStackID == "" {
		buildStackID = stackMD.BuildImage.StackID
	}

	if buildStackID == "" {
		return "", cmd.FailErrCode(
			errors.New("CNB_STACK_ID is required when there is no stack metadata available"),
			cmd.CodeInvalidArgs,
			"parse arguments",
		)
	}
	return buildStackID, nil
}

func (a *analyzeCmd) resolveRunImage(stackMD platform.StackMetadata) (imgutil.Image, error) {
	runImageRef := a.runImageRef
	if runImageRef == "" {
		runImageRef = stackMD.RunImage.Image
	}
	useRunImageMirrors := stackMD.RunImage.Image != "" && a.imageName != ""

	if runImageRef == "" {
		return nil, cmd.FailErrCode(
			errors.New("CNB_RUN_IMAGE is required when there is no stack metadata available"),
			cmd.CodeInvalidArgs,
			"parse arguments",
		)
	}

	if useRunImageMirrors {
		ref, err := name.ParseReference(a.imageName, name.WeakValidation)
		if err != nil {
			return nil, cmd.FailErr(err, "failed to parse registry")
		}

		registry := ref.Context().RegistryStr()

		runImageRef, err = stackMD.BestRunImageMirror(registry)
		if err != nil {
			return nil, cmd.FailErr(err, "run image mirror")
		}
	}

	var runImage imgutil.Image
	var err error
	if a.useDaemon {
		runImage, err = local.NewImage(
			runImageRef,
			a.docker,
			local.FromBaseImage(runImageRef),
		)
	} else {
		runImage, err = remote.NewImage(
			runImageRef,
			a.keychain,
			remote.FromBaseImage(runImageRef),
		)
	}
	return runImage, err
}

func (a *analyzeCmd) registryImages() []string {
	var registryImages []string
	if a.platform06.cacheImageTag != "" {
		registryImages = append(registryImages, a.platform06.cacheImageTag)
	}
	if !a.useDaemon {
		registryImages = append(registryImages, a.analyzeArgs.imageName)
	}
	return registryImages
}

func (a *analyzeCmd) restoresLayerMetadata() bool {
	return !a.platformAPIVersionGreaterThan06()
}

func (a *analyzeCmd) supportsImageArgument() bool {
	return !a.platformAPIVersionGreaterThan06()
}

func (a *analyzeCmd) supportsStackValidation() bool {
	return a.platformAPIVersionGreaterThan06()
}

func (a *analyzeCmd) platformAPIVersionGreaterThan06() bool {
	return api.MustParse(a.platform.API()).Compare(api.MustParse("0.7")) >= 0
}
