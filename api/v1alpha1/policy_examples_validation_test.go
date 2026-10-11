package v1alpha1

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	schemavalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"sigs.k8s.io/yaml"
)

func TestPolicyExamplesMatchGeneratedCRDs(t *testing.T) {
	for _, test := range []struct {
		name, example, crd string
	}{
		{name: "policy", example: "policy.yaml", crd: "core.orka.ai_agentpolicies.yaml"},
		{name: "binding", example: "binding.yaml", crd: "core.orka.ai_agentpolicybindings.yaml"},
	} {
		t.Run(test.name, func(t *testing.T) {
			crdRaw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd", "bases", test.crd))
			if err != nil {
				t.Fatal(err)
			}
			var definition apiextensionsv1.CustomResourceDefinition
			if err := yaml.Unmarshal(crdRaw, &definition); err != nil {
				t.Fatal(err)
			}
			var schema apiextensions.JSONSchemaProps
			if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
				definition.Spec.Versions[0].Schema.OpenAPIV3Schema, &schema, nil); err != nil {
				t.Fatal(err)
			}
			validator, _, err := schemavalidation.NewSchemaValidator(&schema)
			if err != nil {
				t.Fatal(err)
			}
			exampleRaw, err := os.ReadFile(filepath.Join("..", "..", "examples", "policy", test.example))
			if err != nil {
				t.Fatal(err)
			}
			var example map[string]any
			if err := yaml.Unmarshal(exampleRaw, &example); err != nil {
				t.Fatal(err)
			}
			if errs := schemavalidation.ValidateCustomResource(nil, example, validator); len(errs) != 0 {
				t.Fatalf("example is invalid against generated CRD: %v", errs)
			}
		})
	}
}
