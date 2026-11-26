package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ise "github.com/netascode/go-ise"
	"github.com/tidwall/gjson"
)

func cacheEndpointState(id string) Endpoint {
	return Endpoint{Id: types.StringValue(id), Name: helpers.NewCaseInsensitiveStringValue(id),
		Mac:                     helpers.NewCaseInsensitiveStringValue("02:CA:00:00:00:01"),
		Description:             types.StringValue("before"),
		CustomAttributes:        types.MapNull(types.StringType),
		StaticProfileAssignment: types.BoolValue(false), StaticGroupAssignment: types.BoolValue(false),
		StaticProfileAssignmentDefined: types.BoolValue(true), StaticGroupAssignmentDefined: types.BoolValue(true)}
}

func cacheEndpointResource(t *testing.T, handler http.HandlerFunc) *EndpointResource {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := ise.NewClient(server.URL, "admin", "test", ise.MaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	return &EndpointResource{client: &client, cache: NewThreadSafeCache(), cacheEnabled: true}
}

func cacheTFState(t *testing.T, r *EndpointResource, model Endpoint) tfsdk.State {
	t.Helper()
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	state := tfsdk.State{Schema: schemaResp.Schema}
	if d := state.Set(context.Background(), &model); d.HasError() {
		t.Fatal(d)
	}
	return state
}

func TestProviderEndpointCache(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     types.Bool
		enabled   bool
		wantError bool
	}{
		{"default", types.BoolNull(), false, false},
		{"enabled", types.BoolValue(true), true, false},
		{"disabled", types.BoolValue(false), false, false},
		{"unknown", types.BoolUnknown(), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &IseProvider{}
			var schemaResp provider.SchemaResponse
			p.Schema(context.Background(), provider.SchemaRequest{}, &schemaResp)
			config := IseProviderModel{Username: types.StringValue("admin"), Password: types.StringValue("test"),
				URL: types.StringValue("http://127.0.0.1"), Insecure: types.BoolNull(),
				Retries: types.Int64Null(), RequestTimeout: types.Int64Null(), EndpointCache: tc.value}
			state := tfsdk.State{Schema: schemaResp.Schema}
			if d := state.Set(context.Background(), &config); d.HasError() {
				t.Fatal(d)
			}
			var resp provider.ConfigureResponse
			p.Configure(context.Background(), provider.ConfigureRequest{Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: state.Raw}}, &resp)
			if resp.Diagnostics.HasError() != tc.wantError {
				t.Fatal(resp.Diagnostics)
			}
			if tc.wantError {
				if resp.ResourceData != nil {
					t.Fatal("unknown toggle configured a resource client")
				}
				return
			}
			data := resp.ResourceData.(*IseProviderData)
			if data.EndpointCache != tc.enabled {
				t.Fatalf("enabled=%v", data.EndpointCache)
			}
			r := &EndpointResource{}
			r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: data}, &resource.ConfigureResponse{})
			if r.cacheEnabled != tc.enabled {
				t.Fatal("resource did not honor provider setting")
			}
		})
	}
}

func TestEndpointCacheDisabled(t *testing.T) {
	for _, itemStatus := range []int{200, 404, 503} {
		t.Run(fmt.Sprint(itemStatus), func(t *testing.T) {
			var bulkCalls, itemCalls atomic.Int32
			r := cacheEndpointResource(t, func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/api/v1/endpoint" {
					bulkCalls.Add(1)
					w.WriteHeader(500)
					return
				}
				itemCalls.Add(1)
				w.WriteHeader(itemStatus)
				fmt.Fprint(w, `{"ERSEndPoint":{"id":"test","name":"test","mac":"02:CA:00:00:00:01","description":"after","staticProfileAssignment":false,"staticGroupAssignment":false}}`)
			})
			r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: &IseProviderData{Client: r.client, Cache: r.cache, EndpointCache: false}}, &resource.ConfigureResponse{})
			state := cacheTFState(t, r, cacheEndpointState("test"))
			resp := resource.ReadResponse{State: state}
			r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)
			if bulkCalls.Load() != 0 || itemCalls.Load() != 1 {
				t.Fatalf("bulk=%d item=%d", bulkCalls.Load(), itemCalls.Load())
			}
			if (itemStatus == 503) != resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
			if (itemStatus == 404) != resp.State.Raw.IsNull() {
				t.Fatal("unexpected resource removal")
			}
			if len(r.cache.items) != 0 {
				t.Fatal("disabled cache populated inventory")
			}
		})
	}
}

func TestEndpointCacheReadFallback(t *testing.T) {
	for _, bulk := range []string{"404", "503", "wrapped", "missing"} {
		for _, itemStatus := range []int{200, 404, 503} {
			t.Run(fmt.Sprintf("%s/item%d", bulk, itemStatus), func(t *testing.T) {
				var bulkCalls, itemCalls atomic.Int32
				r := cacheEndpointResource(t, func(w http.ResponseWriter, req *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if req.URL.Path == "/api/v1/endpoint" {
						bulkCalls.Add(1)
						switch bulk {
						case "404":
							w.WriteHeader(404)
							fmt.Fprint(w, `{}`)
						case "503":
							w.WriteHeader(503)
							fmt.Fprint(w, `{}`)
						case "wrapped":
							fmt.Fprint(w, `{"response":[]}`)
						case "missing":
							fmt.Fprint(w, `[]`)
						}
						return
					}
					itemCalls.Add(1)
					w.WriteHeader(itemStatus)
					fmt.Fprint(w, `{"ERSEndPoint":{"id":"test","name":"test","mac":"02:CA:00:00:00:01","description":"after","staticProfileAssignment":false,"staticGroupAssignment":false}}`)
				})
				state := cacheTFState(t, r, cacheEndpointState("test"))
				for i := 0; i < 3; i++ {
					resp := resource.ReadResponse{State: state}
					r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)
					if (itemStatus == 503) != resp.Diagnostics.HasError() {
						t.Fatalf("diagnostics: %v", resp.Diagnostics)
					}
					if (itemStatus == 404) != resp.State.Raw.IsNull() {
						t.Fatalf("unexpected resource removal: %v", resp.State.Raw)
					}
					if itemStatus == 200 {
						var got Endpoint
						if d := resp.State.Get(context.Background(), &got); d.HasError() {
							t.Fatal(d)
						}
						if got.Description.ValueString() != "after" {
							t.Fatal("direct GET not mapped into state")
						}
					}
				}
				if bulkCalls.Load() != 1 || itemCalls.Load() != 3 {
					t.Fatalf("requests bulk=%d item=%d", bulkCalls.Load(), itemCalls.Load())
				}
			})
		}
	}
}

func TestEndpointCachePagination(t *testing.T) {
	for _, mode := range []string{"normal", "repeated", "missing-id"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			r := cacheEndpointResource(t, func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				page := req.URL.Query().Get("page")
				items := make([]map[string]any, 0)
				if page == "1" || mode == "repeated" {
					for i := 0; i < 100; i++ {
						items = append(items, map[string]any{"id": fmt.Sprint(i)})
					}
				} else {
					items = append(items, map[string]any{"id": "last", "customAttributes": map[string]any{"flag": "true"}})
				}
				if mode == "missing-id" {
					delete(items[0], "id")
				}
				_ = json.NewEncoder(w).Encode(items)
			})
			body, err := r.ReadCache(context.Background(), cacheEndpointState("last"))
			if mode != "normal" {
				if err == nil {
					t.Fatal("broken pagination accepted")
				}
				if len(r.cache.items) != 0 {
					t.Fatal("partial snapshot cached")
				}
				if mode == "repeated" && !strings.Contains(err.Error(), "no progress") {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if body.Get("ERSEndPoint.customAttributes.customAttributes.flag").String() != "true" {
				t.Fatal("custom attribute rewrite lost")
			}
			if !body.Get("ERSEndPoint.staticGroupAssignmentDefined").Bool() {
				t.Fatal("state-only flag lost")
			}
			if _, err = r.ReadCache(context.Background(), cacheEndpointState("last")); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("got %d pages", calls.Load())
			}
		})
	}
}

func TestThreadSafeCacheConcurrentFailureAndRecovery(t *testing.T) {
	cache := NewThreadSafeCache()
	var loads atomic.Int32
	var wg sync.WaitGroup
	failure := errors.New("bulk unavailable")
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := cache.GetOrLoad("Endpoint", func() (map[string]gjson.Result, error) { loads.Add(1); return nil, failure })
			if !errors.Is(err, failure) {
				t.Errorf("error: %v", err)
			}
		}()
	}
	wg.Wait()
	if loads.Load() != 1 {
		t.Fatalf("failed bulk loaded %d times", loads.Load())
	}
	cache.Delete("Endpoint")
	_, _, err := cache.GetOrLoad("Endpoint", func() (map[string]gjson.Result, error) { loads.Add(1); return map[string]gjson.Result{}, nil })
	if err != nil || loads.Load() != 2 {
		t.Fatal("cache did not recover after invalidation")
	}
}

func TestThreadSafeCacheInvalidatesInFlightSnapshot(t *testing.T) {
	cache := NewThreadSafeCache()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan gjson.Result, 1)
	var loads atomic.Int32
	go func() {
		items, _, _ := cache.GetOrLoad("Endpoint", func() (map[string]gjson.Result, error) {
			if loads.Add(1) == 1 {
				close(started)
				<-release
				return map[string]gjson.Result{"test": gjson.Parse(`"before"`)}, nil
			}
			return map[string]gjson.Result{"test": gjson.Parse(`"after"`)}, nil
		})
		done <- items["test"]
	}()
	<-started
	cache.Delete("Endpoint") // Successful write while the old snapshot is loading.
	close(release)
	select {
	case result := <-done:
		if result.String() != "after" || loads.Load() != 2 {
			t.Fatal("stale in-flight snapshot served")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cache load deadlocked")
	}
}

func TestEndpointCacheInvalidationAfterWrites(t *testing.T) {
	for _, operation := range []string{"create", "create-existing", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			var r *EndpointResource
			var loadedDuringWrite bool
			r = cacheEndpointResource(t, func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "GET" {
					// Force a Read to load the pre-write snapshot during the API call.
					_, _, _ = r.cache.GetOrLoad("Endpoint", func() (map[string]gjson.Result, error) {
						loadedDuringWrite = true
						return map[string]gjson.Result{}, nil
					})
					if req.Method == "POST" {
						if operation == "create-existing" {
							w.WriteHeader(409)
							return
						}
						w.Header().Set("Location", "/ers/config/endpoint/test")
						w.WriteHeader(201)
						return
					}
				}
				fmt.Fprint(w, `{"ERSEndPoint":{"id":"test","name":"test","profileId":"","groupId":""}}`)
			})
			model := cacheEndpointState("test")
			state := cacheTFState(t, r, model)
			plan := tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}
			switch operation {
			case "create", "create-existing":
				var resp resource.CreateResponse
				resp.State = state
				r.Create(context.Background(), resource.CreateRequest{Plan: plan}, &resp)
				if resp.Diagnostics.HasError() {
					t.Fatal(resp.Diagnostics)
				}
			case "update":
				var resp resource.UpdateResponse
				resp.State = state
				r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: state}, &resp)
				if resp.Diagnostics.HasError() {
					t.Fatal(resp.Diagnostics)
				}
			case "delete":
				resp := resource.DeleteResponse{State: state}
				r.Delete(context.Background(), resource.DeleteRequest{State: state}, &resp)
				if resp.Diagnostics.HasError() {
					t.Fatal(resp.Diagnostics)
				}
			}
			if !loadedDuringWrite {
				t.Fatal("pre-write snapshot was not loaded")
			}
			if _, exists := r.cache.items["Endpoint"]; exists {
				t.Fatal("write left stale snapshot cached")
			}
		})
	}
}
