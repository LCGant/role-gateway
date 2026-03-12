package configx

import (
	"fmt"
	"log"
)

// LoadAll executes each step in order, returning the first error.
func LoadAll(steps ...func() error) error {
	for _, step := range steps {
		if step == nil {
			continue
		}
		err := func() (err error) {
			defer func() {
				if rec := recover(); rec != nil {
					err = panicErr(rec)
					if LoadAllPanicHook != nil {
						LoadAllPanicHook(err)
					} else {
						log.Printf("LoadAll panic: %v", err)
					}
				}
			}()
			return step()
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func panicErr(v any) error {
	if e, ok := v.(error); ok {
		return e
	}
	return fmt.Errorf("panic: %v", v)
}

var LoadAllPanicHook func(error)
