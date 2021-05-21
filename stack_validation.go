package lifecycle

import (
	"fmt"
	"os"

	"github.com/buildpacks/imgutil"
	"github.com/pkg/errors"

	"github.com/buildpacks/lifecycle/cmd"
	"github.com/buildpacks/lifecycle/platform"
)

func ValidateStack(stackMD platform.StackMetadata, runImage imgutil.Image) error {
	buildStackID, err := getBuildStack(stackMD)
	if err != nil {
		return err
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

func getBuildStack(stackMD platform.StackMetadata) (string, error) {
	buildStackID := os.Getenv(cmd.EnvStackID)
	if buildStackID == "" {
		buildStackID = stackMD.BuildImage.StackID
	}

	if buildStackID == "" {
		return "", errors.New("CNB_STACK_ID is required when there is no stack metadata available")
	}
	return buildStackID, nil
}
