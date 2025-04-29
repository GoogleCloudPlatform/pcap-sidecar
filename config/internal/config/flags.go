package config

import (
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/google/go-jsonnet"
	"github.com/spf13/pflag"
	sf "github.com/wissance/stringFormatter"
)

const (
	flagVarPrefix   = "pcap"
	flagVarTemplate = "{0}_{1}"
)

func newFlagVarKey(
	flag *pflag.Flag,
) string {
	name := strings.ToUpper(flag.Name)
	return sf.Format(extVarTemplate, name)
}

func newFlagVarName(
	ev *variable,
) string {
	return sf.Format(flagVarTemplate, flagVarPrefix, ev.name)
}

func setFlagVar(
	vm *jsonnet.VM,
	flag *pflag.Flag,
) {
	key := newFlagVarKey(flag)
	value := flag.DefValue
	if flag.Changed {
		value = flag.Value.String()
	}
	vm.ExtVar(key, value)
}

func loadFlagVariables(
	vm *jsonnet.VM,
	flags *pflag.FlagSet,
) *jsonnet.VM {
	flags.Visit(func(
		flag *pflag.Flag,
	) {
		setFlagVar(vm, flag)
	})
	return vm
}

func registerBooleanFlag(
	flags *pflag.FlagSet,
	name *string,
	cv *ctxVar,
	ev *variable,
) error {
	if value, err := strconv.
		ParseBool(ev.defaultValue); err == nil {
		flags.Bool(*name, value, ev.defaultValue)
		return nil
	} else {
		return errors.Join(errors.New(
			sf.Format("invalid boolean value: {0}", ev.defaultValue),
		), err)
	}
}

func logFlagRegistrationError(
	v *variable,
	err error,
) {
	log.Println(
		sf.Format("failed to parse flag '{0}': {1}", v.name, err.Error()),
	)
}

func registerFlag(
	flags *pflag.FlagSet,
	cv *ctxVar,
	ev *variable,
) error {
	var err error = nil

	name := newFlagVarName(ev)

	switch cv.typ {
	case TYPE_STRING:
		flags.String(name, ev.defaultValue, ev.description)
	case TYPE_BOOLEAN:
		err = registerBooleanFlag(flags, &name, cv, ev)
	default:
		path := sf.Format("flag::{0}", ev.name)
		err = newInvalidConfigValueTypeError(&path)
	}

	return err
}

func RegisterFlags(
	flags *pflag.FlagSet,
) {
	for k, ev := range envVars {
		if cv, ok := ctxVars[k]; ok {
			if err := registerFlag(flags, cv, ev); err != nil {
				logFlagRegistrationError(ev, err)
			}
		}
	}
}
