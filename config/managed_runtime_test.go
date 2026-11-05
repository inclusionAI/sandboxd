package config

import "testing"

func TestManagedRuntimeMinimumStorage(t *testing.T) {
	for _, tc := range []struct {
		profile ManagedRuntimeProfile
		want    uint64
	}{
		{ManagedRuntimeProfile{WritableMB: 4096}, 8192},
		{ManagedRuntimeProfile{WritableMB: 4096, MinimumRootMB: 8192}, 12288},
		{ManagedRuntimeProfile{WritableMB: 4096, MinimumRootMB: -1}, 0},
		{ManagedRuntimeProfile{WritableMB: 0}, 0},
		{ManagedRuntimeProfile{WritableMB: 1 << 44}, 0},
	} {
		got, err := tc.profile.MinimumStorageMB()
		if tc.want == 0 {
			if err == nil {
				t.Fatal("invalid geometry accepted")
			}
		} else if err != nil || got != tc.want {
			t.Fatalf("got %d, %v; want %d", got, err, tc.want)
		}
	}
}
