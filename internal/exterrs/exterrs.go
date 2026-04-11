package exterrs

import "errors"

/*
	errors.Join() method is available since Go version 1.20. I'm using an
	older version of Go, so the need for a custom function
*/
func Join(errs []error) error {
	var nonNil []error
	for _, e := range errs {
		if e != nil {
			nonNil = append(nonNil, e)
		}
	}
	if len(nonNil) == 0 {
		return nil
	}
	msg := ""
	for i, e := range nonNil {
		if i > 0 {
			msg += "; "
		}
		msg += e.Error()
	}
	return errors.New(msg)
}
