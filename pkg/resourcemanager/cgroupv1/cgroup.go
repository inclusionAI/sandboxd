// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroupv1

import (
	"bufio"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

type Cgroup struct {
	CPUAcct CPUAcct
}

func sysfsRead(rootDir string, file string) (string, error) {
	file = path.Join(rootDir, file)
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NONBLOCK, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	return string(data), err
}

func checkFileExists(file string) bool {
	checkFileFunc := func() (result bool, done bool) {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorf("CheckFileExistsInPanic File:%s Error:%+v", file, r)
				result, done = false, false
			}
		}()
		info, err := os.Stat(file)
		if os.IsNotExist(err) || info == nil {
			return false, true
		}
		return !info.IsDir(), true
	}
	for i := 0; i < 3; i++ {
		if result, done := checkFileFunc(); done {
			return result
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func writeFile(filePath string, content string) error {
	if checkFileExists(filePath) {
		if err := os.Remove(filePath); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(file)
	_, err = bw.WriteString(content)
	bw.Flush()
	file.Close()
	return err
}

func rawInt(cgroupPath string, fileName string) (int64, error) {
	content, err := sysfsRead(cgroupPath, fileName)
	if err != nil {
		return 0, err
	} else {
		usageStr := strings.Trim(content, "\n")
		usage, err := strconv.ParseInt(usageStr, 10, 64)
		return usage, err
	}
}
