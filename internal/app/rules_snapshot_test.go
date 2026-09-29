package app

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRuleSnapshotMatchesDuringConcurrentRebuilds(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "rules.txt")
	if err := os.WriteFile(file, []byte("||stable.example.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewRuleStore(file)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}

	const workers = 24
	const iterations = 200
	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for index := 0; index < iterations; index++ {
				action, _, matched := store.Match("child.stable.example")
				if !matched || action != ActionBlock {
					t.Errorf("stable local rule disappeared during snapshot rebuild: action=%q matched=%v", action, matched)
					return
				}
				_ = store.List()
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		for version := 0; version < iterations; version++ {
			entries := make([]RuleEntry, 0, 128)
			for index := 0; index < cap(entries); index++ {
				entries = append(entries, RuleEntry{Domain: "remote" + string(rune('a'+index%26)) + ".example", Action: ActionBlock, Source: "https://rules.example/list"})
			}
			store.SetRemote("https://rules.example/list", entries)
		}
	}()
	close(start)
	wait.Wait()
}
