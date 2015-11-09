package plugin_test

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"os"
	"plugin"
)

var _ = Describe("Plugin Commands", func() {

	drain := func(file *os.File, output chan string) {
		data, err := ioutil.ReadAll(file)
		if err != nil {
			panic(fmt.Sprintf("Error reading from pipe, test is invalid: %s", err.Error()))
		}
		output <- string(data)
	}

	It("Executes commands successfully", func() {
		rc, err := plugin.ExecWithPipes("test/bin/exec_tester 0", nil, nil, nil)
		Expect(rc).Should(Equal(plugin.SUCCESS))
		Expect(err).ShouldNot(HaveOccurred())
	})
	It("Returns errors when the command fails", func() {
		rc, err := plugin.ExecWithPipes("test/bin/exec_tester 1", nil, nil, nil)
		Expect(rc).Should(Equal(plugin.EXEC_FAILURE))
		Expect(err).Should(HaveOccurred())
	})
	It("Gets stderr/stdout and uses stdin", func() {
		rStdin, wStdin, err := os.Pipe()
		Expect(err).ShouldNot(HaveOccurred())

		rStderr, wStderr, err := os.Pipe()
		Expect(err).ShouldNot(HaveOccurred())
		stderrC := make(chan string)
		go drain(rStderr, stderrC)

		rStdout, wStdout, err := os.Pipe()
		Expect(err).ShouldNot(HaveOccurred())
		stdoutC := make(chan string)
		go drain(rStdout, stdoutC)

		_, err = wStdin.Write([]byte("This should go to stdout"))
		Expect(err).ShouldNot(HaveOccurred())
		wStdin.Close()

		rc, err := plugin.ExecWithPipes("test/bin/exec_tester 0", wStdout, wStderr, rStdin)
		wStderr.Close() // simulate command exiting + its pipe being closed
		wStdout.Close() // simulate command exiting + its pipe being closed

		stderr := <-stderrC
		stdout := <-stdoutC

		Expect(err).ShouldNot(HaveOccurred())
		Expect(rc).Should(Equal(plugin.SUCCESS))
		Expect(stdout).Should(Equal("This should go to stdout"))
		Expect(stderr).Should(Equal("This goes to stderr\n"))
	})
	It("Returns an error for commands that cannot be parsed", func() {
		_, err := plugin.Exec("this '\"cannot be parsed", plugin.NOPIPE)
		Expect(err).Should(HaveOccurred())

	})
})