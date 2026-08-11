package arcjet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

func TestGuardPolicyInputsEncodeAndProtectLocalValue(t *testing.T) {
	list := []string{"one", "two"}
	inputs := map[string]GuardPolicyInput{
		"string":  GuardPolicyServerString("value"),
		"boolean": GuardPolicyServerBoolean(true),
		"integer": GuardPolicyServerInteger(-42),
		"number":  GuardPolicyServerNumber(1.5),
		"list":    GuardPolicyServerStringList(list),
		"local":   GuardPolicyLocalString("private value"),
	}
	list[0] = "mutated"

	wire, _, hasLocal, err := wirePolicyInputs(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !hasLocal {
		t.Fatal("expected local input")
	}
	if got := wire["string"].GetServer().GetStringValue(); got != "value" {
		t.Fatalf("string = %q", got)
	}
	if got := wire["boolean"].GetServer().GetBooleanValue(); !got {
		t.Fatal("boolean = false")
	}
	if got := wire["integer"].GetServer().GetIntegerValue(); got != -42 {
		t.Fatalf("integer = %d", got)
	}
	if got := wire["number"].GetServer().GetNumberValue(); got != 1.5 {
		t.Fatalf("number = %f", got)
	}
	if got := wire["list"].GetServer().GetStringListValue().GetValues()[0]; got != "one" {
		t.Fatalf("copied list[0] = %q", got)
	}
	if got := hex.EncodeToString(wire["local"].GetLocal().GetValueSha256()); got == "" {
		t.Fatal("local digest is empty")
	}

	encoded, err := proto.Marshal(&decidev2.GuardRequest{PolicyInputs: wire})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("private value")) {
		t.Fatal("serialized request contains raw local value")
	}

	if got := hex.EncodeToString(localPolicyDigest("hello")); got != "344c730291b0156792dbdd8e4528370616e70ba828e9f4c614491b46cbcd4f8a" {
		t.Fatalf("hello digest = %s", got)
	}
}

func TestGuardPolicyInputsRejectInvalidValues(t *testing.T) {
	for name, inputs := range map[string]map[string]GuardPolicyInput{
		"nil":      {"bad": nil},
		"nan":      {"bad": GuardPolicyServerNumber(math.NaN())},
		"infinity": {"bad": GuardPolicyServerNumber(math.Inf(1))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := wirePolicyInputs(inputs); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

type blockingPolicyClient struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
	resp    *decidev2.GetGuardPolicyResponse
	err     error
}

func (c *blockingPolicyClient) GetGuardPolicy(ctx context.Context, _ *connect.Request[decidev2.GetGuardPolicyRequest]) (*connect.Response[decidev2.GetGuardPolicyResponse], error) {
	c.mu.Lock()
	c.calls++
	if c.calls == 1 && c.started != nil {
		close(c.started)
	}
	c.mu.Unlock()
	if c.release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.release:
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	return connect.NewResponse(c.resp), nil
}

func (c *blockingPolicyClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestRemotePolicyFetchCancellationDoesNotCancelSharedFetch(t *testing.T) {
	client := &blockingPolicyClient{
		started: make(chan struct{}),
		release: make(chan struct{}),
		resp: &decidev2.GetGuardPolicyResponse{
			Status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
			Policy: &decidev2.GuardLocalPolicyProjection{PolicyId: "policy", Revision: "rev"},
		},
	}
	runtime := newRemotePolicyRuntime(client, "key", "ua", newLazyLocalEvaluator(nil), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runtime.get(ctx, "label", false)
		done <- err
	}()
	<-client.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("starter error = %v", err)
	}

	waiter := make(chan policyCacheEntry, 1)
	go func() {
		entry, _ := runtime.get(context.Background(), "label", false)
		waiter <- entry
	}()
	close(client.release)
	if entry := <-waiter; entry.policy == nil || entry.policy.GetRevision() != "rev" {
		t.Fatalf("shared result = %#v", entry)
	}
	if got := client.callCount(); got != 1 {
		t.Fatalf("GetGuardPolicy calls = %d", got)
	}
}

func TestRemotePolicyFetchFailureIsCachedUnavailableWithoutFailingGuardPreparation(t *testing.T) {
	client := &blockingPolicyClient{err: errors.New("unavailable")}
	runtime := newRemotePolicyRuntime(client, "key", "ua", newLazyLocalEvaluator(nil), nil)
	prepared, err := runtime.prepare(
		context.Background(),
		"label",
		map[string]GuardPolicyInput{"body": GuardPolicyLocalString("private")},
		false,
	)
	if err != nil {
		t.Fatalf("prepare error = %v", err)
	}
	if !prepared.hasLocal || prepared.decision != nil || prepared.revision != "" || len(prepared.results) != 0 || prepared.inputs["body"].GetLocal() == nil {
		t.Fatalf("prepared policy = %#v", prepared)
	}
	if got := client.callCount(); got != 1 {
		t.Fatalf("GetGuardPolicy calls = %d", got)
	}
}

type policySensitiveInfoBackend struct{}

func (policySensitiveInfoBackend) Detect(
	context.Context,
	SensitiveInfoBackendContext,
	string,
	SensitiveInfoEntities,
	*SensitiveInfoBackendOptions,
) (SensitiveInfoResult, error) {
	return SensitiveInfoResult{
		Allowed: []DetectedSensitiveInfoEntity{{Start: 0, End: 4, Type: SensitiveInfoCity}},
		Denied: []DetectedSensitiveInfoEntity{
			{Start: 5, End: 10, Type: SensitiveInfoEmail},
			{Start: 11, End: 16, Type: SensitiveInfoEmail},
			{Start: 17, End: 20, Type: EntityType("UNKNOWN_BACKEND_TYPE")},
		},
	}, nil
}

type policyAllowedOnlyBackend struct{}

func (policyAllowedOnlyBackend) Detect(
	context.Context,
	SensitiveInfoBackendContext,
	string,
	SensitiveInfoEntities,
	*SensitiveInfoBackendOptions,
) (SensitiveInfoResult, error) {
	return SensitiveInfoResult{
		Allowed: []DetectedSensitiveInfoEntity{{Start: 0, End: 4, Type: SensitiveInfoEmail}},
	}, nil
}

func TestRemotePolicyLocalEvidenceIsMinimalAndDeduplicated(t *testing.T) {
	now := time.Now()
	runtime := newRemotePolicyRuntime(&blockingPolicyClient{}, "key", "ua", newLazyLocalEvaluator(nil), policySensitiveInfoBackend{})
	runtime.cache["label"] = policyCacheEntry{
		status: decidev2.GuardPolicyLookupStatus_GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
		policy: &decidev2.GuardLocalPolicyProjection{
			PolicyId: "policy-id",
			Revision: "revision-1",
			SensitiveInfoRules: []*decidev2.GuardLocalSensitiveInfoRule{{
				RuleId:       "rule-id",
				InputName:    "body",
				EntityFilter: &decidev2.GuardLocalSensitiveInfoRule_EntitiesDeny{EntitiesDeny: &decidev2.EntityList{Entities: []string{"EMAIL"}}},
			}},
		},
		refreshAt: now.Add(time.Minute),
	}
	prepared, err := runtime.prepare(context.Background(), "label", map[string]GuardPolicyInput{"body": GuardPolicyLocalString("private body")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.revision != "revision-1" || len(prepared.results) != 1 {
		t.Fatalf("revision/results = %q/%d", prepared.revision, len(prepared.results))
	}
	result := prepared.results[0]
	if result.GetPolicyId() != "policy-id" || result.GetRuleId() != "rule-id" || result.GetInputName() != "body" {
		t.Fatalf("local evidence identity = %#v", result)
	}
	computed := result.GetLocalSensitiveInfo()
	if computed == nil || !computed.GetDetected() || computed.GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_DENY {
		t.Fatalf("computed result = %#v", computed)
	}
	if got := computed.GetDetectedEntityTypes(); len(got) != 1 || got[0] != "EMAIL" {
		t.Fatalf("detected types = %#v", got)
	}
	if got := computed.GetDetectedEntities(); len(got) != 2 || got[0].GetType() != "EMAIL" || got[1].GetType() != "EMAIL" {
		t.Fatalf("detected entities = %#v", got)
	}
}

func TestRemotePolicyAllowedOnlyDetectionProducesNoDeniedEvidence(t *testing.T) {
	runtime := newRemotePolicyRuntime(&blockingPolicyClient{}, "key", "ua", newLazyLocalEvaluator(nil), policyAllowedOnlyBackend{})
	policy := &decidev2.GuardLocalPolicyProjection{PolicyId: "policy-id", Revision: "revision-1"}
	rule := &decidev2.GuardLocalSensitiveInfoRule{
		RuleId:       "rule-id",
		InputName:    "body",
		EntityFilter: &decidev2.GuardLocalSensitiveInfoRule_EntitiesAllow{EntitiesAllow: &decidev2.EntityList{Entities: []string{"EMAIL"}}},
	}

	result := runtime.localResult(context.Background(), policy, rule, "private body")
	computed := result.GetLocalSensitiveInfo()
	if computed == nil {
		t.Fatal("missing computed result")
	}
	if computed.GetDetected() || computed.GetConclusion() != decidev2.GuardConclusion_GUARD_CONCLUSION_ALLOW {
		t.Fatalf("allowed-only result = %#v", computed)
	}
	if len(computed.GetDetectedEntityTypes()) != 0 || len(computed.GetDetectedEntities()) != 0 {
		t.Fatalf("allowed-only evidence = types:%#v entities:%#v", computed.GetDetectedEntityTypes(), computed.GetDetectedEntities())
	}
}
