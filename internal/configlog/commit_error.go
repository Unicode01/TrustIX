package configlog

import "errors"

// CommitError reports a failure after an atomic replacement became visible.
// Callers must treat the new state as committed and reconcile follow-up work.
type CommitError struct {
	Err error
}

func (err *CommitError) Error() string {
	if err == nil || err.Err == nil {
		return "config log commit completed with an unknown durability error"
	}
	return err.Err.Error()
}

func (err *CommitError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func CommitSucceeded(err error) bool {
	var committed *CommitError
	return errors.As(err, &committed)
}
