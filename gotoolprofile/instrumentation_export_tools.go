package gotoolprofile

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// This is diagnostic projection only. Exact tool-state equality remains the
// permission guard; neither these digests nor the changed-field list authorize
// a route. Physical directories, origins and unknown map keys are not printed.
func instrumentationExportToolDifference(before, after *discoveryFeatureToolState) (string, error) {
	beforeSHA, err := instrumentationExportToolStateSHA(before)
	if err != nil {
		return "", err
	}
	afterSHA, err := instrumentationExportToolStateSHA(after)
	if err != nil {
		return "", err
	}

	var fields []string
	if before == nil || after == nil {
		fields = append(fields, "state_presence")
	} else {
		if before.directory != after.directory {
			fields = append(fields, "directory")
		}
		if before.routing != after.routing {
			fields = append(fields, "routing_sha256")
		}
		if before.dispatcher != after.dispatcher {
			fields = append(fields, "dispatcher_sha256")
		}
		fields = append(fields, instrumentationExportToolMapDifference("binary_sha256", before.digests, after.digests)...)
		fields = append(fields, instrumentationExportToolMapDifference("binary_origins", before.origins, after.origins)...)
	}

	return fmt.Sprintf("fields=%s before_sha256=%s after_sha256=%s", strings.Join(fields, ","), beforeSHA, afterSHA), nil
}

func instrumentationExportToolMapDifference(field string, before, after map[string]string) []string {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	fields := []string{field}
	for _, tool := range []string{"asm", "compile", "link", "nm", "vet"} {
		beforeValue, beforeExists := before[tool]
		afterValue, afterExists := after[tool]
		if beforeExists != afterExists || beforeValue != afterValue {
			fields = append(fields, field+"["+tool+"]")
		}
	}
	return fields
}

func instrumentationExportToolStateSHA(state *discoveryFeatureToolState) (string, error) {
	// Use explicitly exported fields: directly marshaling the private state would
	// otherwise discard its entire identity. Nil maps and states remain distinct.
	type projection struct {
		Directory  string
		Digests    map[string]string
		Origins    map[string]string
		Routing    string
		Dispatcher string
	}
	var identity *projection
	if state != nil {
		identity = &projection{state.directory, state.digests, state.origins, state.routing, state.dispatcher}
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	return discoveryFeatureBytesSHA256(data), nil
}
