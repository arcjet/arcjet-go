// Command example demonstrates the on-device Rampart sensitive-info backend.
// It runs entirely offline (no Arcjet key needed) by calling the backend
// directly; in a real application you pass the backend to a SensitiveInfo rule
// via arcjet.NewClient (see the commented block below).
package main

import (
	"context"
	"fmt"
	"log"

	arcjet "github.com/arcjet/arcjet-go"
	"github.com/arcjet/arcjet-go/sensitiveinfo/rampart"
)

func main() {
	backend, err := rampart.New(rampart.Options{})
	if err != nil {
		log.Fatalf("load rampart backend: %v", err)
	}

	inputs := []string{
		"My name is Sarah and I live in London.",
		"Reach me at john.doe@example.com or (555) 234-5678.",
		"Ship to 123 Main Street, Springfield, IL 62704. SSN 123-45-6789.",
	}

	// Deny every entity type Rampart knows about.
	entities := arcjet.SensitiveInfoEntities{Deny: true, Entities: rampart.Entities()}

	for _, in := range inputs {
		res, err := backend.Detect(context.Background(), arcjet.SensitiveInfoBackendContext{}, in, entities, nil)
		if err != nil {
			log.Fatalf("detect: %v", err)
		}
		fmt.Printf("\n%q\n", in)
		if len(res.Denied) == 0 {
			fmt.Println("  (nothing detected)")
		}
		for _, e := range res.Denied {
			fmt.Printf("  %-18s %q\n", e.Type, in[e.Start:e.End])
		}
	}

	// In a real application, wire the backend into a rule:
	//
	//	client, err := arcjet.NewClient(arcjet.Config{
	//		Rules: []arcjet.Rule{
	//			arcjet.SensitiveInfo(arcjet.SensitiveInfoOptions{
	//				Mode:    arcjet.ModeLive,
	//				Deny:    []arcjet.EntityType{arcjet.SensitiveInfoGivenName},
	//				Backend: backend,
	//			}),
	//		},
	//	})
}
