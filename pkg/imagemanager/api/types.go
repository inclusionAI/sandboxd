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

import "fmt"

type OSSMountRequest struct {
	MountPoint      string `json:"mount_point,omitempty"`
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Object          string `json:"object"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
}

func (req *OSSMountRequest) String() string {
	return fmt.Sprintf("(%s, %s, %s, %s)", req.MountPoint, req.Endpoint, req.Bucket, req.Object)
}

type OSSUmountRequest struct {
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Object   string `json:"object"`
}

func (req *OSSUmountRequest) String() string {
	return fmt.Sprintf("(%s %s %s)", req.Endpoint, req.Bucket, req.Object)
}

type MountInfo struct {
	MountPoint string   `json:"mount_point"`
	FilePath   string   `json:"file_path"`
	Env        []string `json:"env,omitempty"`
}

// OCIMountResponse is returned by the /oci_mount endpoint.
type OCIMountResponse struct {
	MountPath string   `json:"mount_path"`
	Env       []string `json:"env,omitempty"`
}

// RootfsMaterialization locates content-addressed, image-owned storage for a
// derived root filesystem artifact.
type RootfsMaterialization struct {
	ContentID   string
	ArtifactDir string
}

// OCIMountRequest is used to request mounting an OCI image
type OCIMountRequest struct {
	ImageURL string `json:"image_url"` // Image URL, e.g., "library/alpine:latest"
}

func (req *OCIMountRequest) String() string {
	return fmt.Sprintf("(%s)", req.ImageURL)
}

// OCIUmountRequest is used to request unmounting an OCI image
type OCIUmountRequest struct {
	ImageURL string `json:"image_url"` // Image URL
}

func (req *OCIUmountRequest) String() string {
	return fmt.Sprintf("(%s)", req.ImageURL)
}

// NydusMountRequest is used to request mounting a Nydus image
type NydusMountRequest struct {
	ImageURL   string `json:"image_url"`
	MountPoint string `json:"mount_point,omitempty"`
}

func (req *NydusMountRequest) String() string {
	return fmt.Sprintf("(%s, %s)", req.ImageURL, req.MountPoint)
}

// NydusUmountRequest is used to request unmounting a Nydus image
type NydusUmountRequest struct {
	ImageURL string `json:"image_url"`
}

func (req *NydusUmountRequest) String() string {
	return fmt.Sprintf("(%s)", req.ImageURL)
}

// CleanupDaemonRequest is used to request cleanup of a daemon
type CleanupDaemonRequest struct {
	DaemonID string `json:"daemon_id"`
}
