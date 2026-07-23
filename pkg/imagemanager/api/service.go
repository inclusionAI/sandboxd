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

package api

import (
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
)

// Service is the in-process image and mount facade consumed by sandboxd. A
// single HttpWorker implements the interface for each process.
//
// Method names mirror HttpClient's contract (Umount*, not Unmount*) so the
// existing sandboxd call sites switch with a one-line type change rather
// than a method-by-method rename.
type Service interface {
	MountOSS(req *OSSMountRequest) (*MountInfo, error)
	UmountOSS(req *OSSUmountRequest) error
	MountOCI(req *OCIMountRequest) (*OCIMountResponse, error)
	UmountOCI(req *OCIUmountRequest) error
	MountNydus(req *NydusMountRequest) (*MountInfo, error)
	UmountNydus(req *NydusUmountRequest) error
	CleanupDaemon(req *CleanupDaemonRequest) error
	ListDaemons() ([]distillfs.DaemonInfo, error)
	ListMountedOCIImages() ([]string, error)
	ListMountedOCIDetails() ([]oci.OciMountRecord, error)
}

// Compile-time witness that HttpWorker implements Service.
var _ Service = (*HttpWorker)(nil)

// UmountOSS satisfies Service by discarding HttpWorker.UnmountOSS's
// *MountInfo return value, which only existed for the HTTP response body
// and is not consumed by any in-process caller.
func (w *HttpWorker) UmountOSS(req *OSSUmountRequest) error {
	_, err := w.UnmountOSS(req)
	return err
}

// UmountOCI is a renaming shim: HttpClient.UmountOCI matches the existing
// sandboxd call site; HttpWorker exposes the same operation as UnmountOCI.
func (w *HttpWorker) UmountOCI(req *OCIUmountRequest) error {
	return w.UnmountOCI(req)
}

// UmountNydus satisfies Service in the same shape as UmountOSS.
func (w *HttpWorker) UmountNydus(req *NydusUmountRequest) error {
	_, err := w.UnmountNydus(req)
	return err
}
