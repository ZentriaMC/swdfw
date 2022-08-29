package cmdchain

type ErrInterceptor func(error) error

var (
	DefaultErrInterceptor ErrInterceptor = func(err error) error {
		return err
	}
)
