package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PranavRJoshi/Veil/internal/completion"
)

// runComplete is the hidden "__complete" engine the shell wrappers call; it
// prints one candidate per line for the words typed so far.
func runComplete(args []string) int {
	for _, c := range completion.Complete(args) {
		fmt.Println(c)
	}
	return 0
}

// runCompletionCmd handles "completion <shell>", printing a wrapper script the
// user sources. prog is os.Args[0]; its base name is the command the script
// registers against and calls back into.
func runCompletionCmd(prog string, args []string) int {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s completion <bash|zsh>\n", filepath.Base(prog))
		return 2
	}
	cmd := filepath.Base(prog)
	switch args[0] {
	case "bash":
		fmt.Print(strings.ReplaceAll(bashCompletion, "@@CMD@@", cmd))
	case "zsh":
		fmt.Print(strings.ReplaceAll(zshCompletion, "@@CMD@@", cmd))
	default:
		fmt.Fprintf(os.Stderr, "unsupported shell %q (want bash or zsh)\n", args[0])
		return 2
	}
	return 0
}

// The wrappers pass the words after the program name, up to and including the
// (possibly empty) word under the cursor, to "@@CMD@@ __complete", then hand
// its newline-separated output back to the shell. When the engine returns
// nothing (a value's domain is a file path, e.g. --config or config validate),
// the shell falls back to its own path completion: "-o default" in bash, and an
// explicit "_files" in zsh.

const bashCompletion = `_@@CMD@@_complete() {
    local IFS=$'\n'
    local args=("${COMP_WORDS[@]:1:COMP_CWORD}")
    COMPREPLY=($(@@CMD@@ __complete "${args[@]}"))
}
complete -o default -F _@@CMD@@_complete @@CMD@@
`

const zshCompletion = `#compdef @@CMD@@
_@@CMD@@() {
    local -a completions
    completions=(${(f)"$(@@CMD@@ __complete "${(@)words[2,CURRENT]}")"})
    if (( ${#completions} )); then
        compadd -- $completions
    else
        _files
    fi
}
compdef _@@CMD@@ @@CMD@@
`
